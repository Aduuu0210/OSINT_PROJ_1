"""
Core SerpApi client with concurrency, rate-limit backoff, and graceful empty handling.

All external intelligence MUST flow through this module. No other API vendors.
"""

from __future__ import annotations

import logging
import os
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("osint.serpapi")

# SerpApi signals "no results" with this (or very similar) error string
NO_RESULTS_MARKERS = (
    "google hasn't returned any results for this query",
    "hasn't returned any results",
    "no results",
    "could not find any results",
)

# Default concurrency / retry knobs
DEFAULT_MAX_WORKERS = 4
DEFAULT_MAX_RETRIES = 3
DEFAULT_BASE_BACKOFF = 1.5  # seconds
DEFAULT_MAX_BACKOFF = 20.0


class SerpApiError(Exception):
    """Raised for non-recoverable SerpApi failures (auth, billing, etc.)."""


class SerpApiClient:
    """
    Thread-safe SerpApi wrapper.

    - Treats "Google hasn't returned any results for this query" as ``[]``
    - Logs that condition at INFO (never crashes)
    - Parallelizes batches via ``ThreadPoolExecutor``
    - Exponential backoff + jitter on 429 / 5xx / transient errors
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        max_workers: int = DEFAULT_MAX_WORKERS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        base_backoff: float = DEFAULT_BASE_BACKOFF,
    ) -> None:
        self.api_key = (
            api_key
            or os.environ.get("SERPAPI_API_KEY")
            or os.environ.get("SERP_API_KEY")
            or ""
        )
        self.max_workers = max(1, int(max_workers))
        self.max_retries = max(0, int(max_retries))
        self.base_backoff = float(base_backoff)
        self._lock = threading.Lock()
        self._call_count = 0
        self._last_call_ts = 0.0
        # Soft client-side pacing (SerpApi free tier is rate-limited)
        self.min_interval = 0.15  # seconds between outgoing calls per process

        if not self.api_key:
            logger.warning(
                "No SerpApi key configured. Set SERPAPI_API_KEY or pass api_key=..."
            )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _pace(self) -> None:
        """Lightweight inter-call spacing to reduce burst 429s."""
        with self._lock:
            now = time.monotonic()
            delta = now - self._last_call_ts
            if delta < self.min_interval:
                time.sleep(self.min_interval - delta)
            self._last_call_ts = time.monotonic()
            self._call_count += 1

    @staticmethod
    def _is_no_results_error(message: str) -> bool:
        msg = (message or "").lower()
        return any(marker in msg for marker in NO_RESULTS_MARKERS)

    def _import_serpapi(self):
        """Lazy import so the rest of the package can load without the dep installed."""
        try:
            from serpapi import GoogleSearch  # type: ignore
            return GoogleSearch
        except ImportError:
            try:
                # Older package name layout
                from serpapi.google_search import GoogleSearch  # type: ignore
                return GoogleSearch
            except ImportError as exc:
                raise SerpApiError(
                    "serpapi / google-search-results package is not installed. "
                    "Run: pip install google-search-results"
                ) from exc

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def search(
        self,
        params: Dict[str, Any],
        *,
        result_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute a single SerpApi query.

        Returns the full JSON dict. On the canonical "no results" error the
        response is normalized to ``{"organic_results": [], "error": None,
        "_no_results": True, ...}`` so callers never see an exception.
        """
        if not self.api_key:
            raise SerpApiError(
                "Missing SerpApi API key. Export SERPAPI_API_KEY or configure it in the UI."
            )

        payload = dict(params)
        payload["api_key"] = self.api_key
        # Sensible defaults
        payload.setdefault("hl", "en")
        payload.setdefault("gl", "us")

        GoogleSearch = self._import_serpapi()
        last_err: Optional[Exception] = None

        for attempt in range(self.max_retries + 1):
            try:
                self._pace()
                logger.debug(
                    "SerpApi call engine=%s q=%s attempt=%s",
                    payload.get("engine"),
                    payload.get("q") or payload.get("url"),
                    attempt + 1,
                )
                client = GoogleSearch(payload)
                data = client.get_dict() or {}

                # SerpApi embeds errors inside the JSON body
                err = data.get("error")
                if err:
                    err_str = str(err)
                    if self._is_no_results_error(err_str):
                        logger.info(
                            "[INFO] Google hasn't returned any results for this query "
                            "(engine=%s, q=%s) — treating as empty list.",
                            payload.get("engine"),
                            payload.get("q") or payload.get("url"),
                        )
                        data = self._empty_response(payload, marker=err_str)
                        return data

                    # Auth / quota — do not retry forever
                    lower = err_str.lower()
                    if any(
                        s in lower
                        for s in (
                            "invalid api key",
                            "api key has not been found",
                            "run out of searches",
                            "your account has been suspended",
                        )
                    ):
                        raise SerpApiError(err_str)

                    # Transient — back off
                    if attempt < self.max_retries:
                        self._backoff(attempt, reason=err_str)
                        continue
                    raise SerpApiError(err_str)

                return data

            except SerpApiError:
                raise
            except Exception as exc:  # network / parse
                last_err = exc
                msg = str(exc)
                if self._is_no_results_error(msg):
                    logger.info(
                        "[INFO] Google hasn't returned any results for this query "
                        "(exception path) — treating as empty list. detail=%s",
                        msg,
                    )
                    return self._empty_response(payload, marker=msg)

                if attempt < self.max_retries:
                    self._backoff(attempt, reason=msg)
                    continue
                raise SerpApiError(f"SerpApi request failed after retries: {msg}") from exc

        raise SerpApiError(f"SerpApi request failed: {last_err}")

    def search_results(
        self,
        params: Dict[str, Any],
        *,
        keys: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Convenience: run ``search`` and flatten the common result arrays into one list.

        ``keys`` defaults to the usual SerpApi buckets across engines.
        """
        data = self.search(params)
        return self.extract_items(data, keys=keys)

    @staticmethod
    def extract_items(
        data: Dict[str, Any],
        keys: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Pull list-valued result buckets out of a SerpApi response dict."""
        if not data:
            return []
        keys = keys or [
            "organic_results",
            "news_results",
            "local_results",
            "place_results",
            "visual_matches",
            "image_results",
            "inline_images",
            "related_questions",
            "recipes_results",
            "shopping_results",
        ]
        items: List[Dict[str, Any]] = []
        for key in keys:
            bucket = data.get(key)
            if isinstance(bucket, list):
                for entry in bucket:
                    if isinstance(entry, dict):
                        # Tag origin bucket for downstream analytics
                        entry = dict(entry)
                        entry.setdefault("_serpapi_bucket", key)
                        items.append(entry)
            elif isinstance(bucket, dict):
                # place_results is often a single dict for maps
                entry = dict(bucket)
                entry.setdefault("_serpapi_bucket", key)
                items.append(entry)
        return items

    def batch_search(
        self,
        param_list: List[Dict[str, Any]],
        *,
        progress_callback: Optional[Callable[[int, int, Dict[str, Any]], None]] = None,
    ) -> List[Tuple[Dict[str, Any], Dict[str, Any], Optional[str]]]:
        """
        Run many queries concurrently.

        Returns a list of ``(params, response_dict, error_string_or_None)`` in the
        **same order** as ``param_list``.
        """
        if not param_list:
            return []

        total = len(param_list)
        results: List[Optional[Tuple[Dict[str, Any], Dict[str, Any], Optional[str]]]] = [
            None
        ] * total

        def _worker(idx: int, params: Dict[str, Any]):
            try:
                data = self.search(params)
                return idx, params, data, None
            except Exception as exc:
                logger.error("batch item %s failed: %s", idx, exc)
                return idx, params, {}, str(exc)

        workers = min(self.max_workers, total)
        completed = 0
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(_worker, i, p): i for i, p in enumerate(param_list)
            }
            for fut in as_completed(futures):
                idx, params, data, err = fut.result()
                results[idx] = (params, data, err)
                completed += 1
                if progress_callback:
                    try:
                        progress_callback(completed, total, params)
                    except Exception:  # never let UI callback kill the batch
                        logger.exception("progress_callback failed")

        # type: ignore — all slots filled
        return [r for r in results if r is not None]  # type: ignore[misc]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _backoff(self, attempt: int, reason: str = "") -> None:
        delay = min(
            DEFAULT_MAX_BACKOFF,
            self.base_backoff * (2 ** attempt) + random.uniform(0, 0.5),
        )
        logger.warning(
            "Backing off %.2fs after attempt %s (%s)", delay, attempt + 1, reason
        )
        time.sleep(delay)

    @staticmethod
    def _empty_response(params: Dict[str, Any], marker: str = "") -> Dict[str, Any]:
        return {
            "search_metadata": {
                "status": "Success",
                "id": "empty-no-results",
            },
            "search_parameters": {
                k: v for k, v in params.items() if k != "api_key"
            },
            "organic_results": [],
            "news_results": [],
            "local_results": [],
            "visual_matches": [],
            "error": None,
            "_no_results": True,
            "_no_results_marker": marker,
        }

    @property
    def call_count(self) -> int:
        with self._lock:
            return self._call_count
