"""
Google Lens module (engine="google_lens").

Accepts an image URL and searches for reused avatars, catfish accounts,
and reverse-image matches.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, List, Optional

from ..models import AttemptedQuery, OSINTResult, filter_valid_hits, is_valid_hit
from ..serpapi_client import SerpApiClient

logger = logging.getLogger("osint.modules.lens_search")

ProgressCb = Optional[Callable[[str], None]]


class LensSearchModule:
    """Reverse-image investigation via Google Lens."""

    name = "lens_search"
    engine = "google_lens"

    def __init__(self, client: SerpApiClient) -> None:
        self.client = client

    def run(
        self,
        target: str,
        *,
        image_url: Optional[str] = None,
        progress: ProgressCb = None,
    ) -> Dict[str, Any]:
        """
        ``target`` is used for anti-FP filtering (name/handle associated with the image).
        ``image_url`` is the actual Lens input; falls back to ``target`` if it looks like a URL.
        """
        url = (image_url or "").strip() or (target if str(target).startswith("http") else "")
        results: List[OSINTResult] = []
        attempted: List[AttemptedQuery] = []

        if not url:
            msg = "No image URL provided for Google Lens search."
            logger.warning(msg)
            if progress:
                progress(f"[lens_search] SKIP — {msg}")
            attempted.append(
                AttemptedQuery(
                    module=self.name,
                    engine=self.engine,
                    query="(no image url)",
                    status="error",
                    error_message=msg,
                )
            )
            return {"results": results, "attempted": attempted}

        if progress:
            progress(f"[lens_search] Reverse-image lookup via Google Lens: {url}")

        params = {
            "engine": self.engine,
            "url": url,
        }

        t0 = time.monotonic()
        try:
            data = self.client.search(params)
            err = None
        except Exception as exc:
            data = {}
            err = str(exc)

        duration = (time.monotonic() - t0) * 1000.0

        if err:
            attempted.append(
                AttemptedQuery(
                    module=self.name,
                    engine=self.engine,
                    query=url,
                    status="error",
                    error_message=err,
                    duration_ms=duration,
                )
            )
            if progress:
                progress(f"[lens_search] ERROR — {err}")
            return {"results": results, "attempted": attempted}

        raw_items = self.client.extract_items(
            data,
            keys=[
                "visual_matches",
                "image_results",
                "online_matches",
                "exact_matches",
                "organic_results",
            ],
        )

        # For Lens, the "target" for FP filtering is ambiguous (image bytes, not text).
        # Strategy:
        #   1. If a textual target distinct from the URL was supplied, require is_valid_hit.
        #   2. Otherwise keep all visual matches (they are inherently image-similar).
        textual_target = target if target and target != url and not str(target).startswith("http") else ""

        if textual_target:
            valid = filter_valid_hits(textual_target, raw_items)
            # Also keep exact/high-confidence visual matches even if text doesn't match —
            # but tag them; we still prefer text-validated ones first.
            if not valid:
                # Fall back to all matches but mark module accordingly
                valid = raw_items
                module_tag = f"{self.name}:visual_unfiltered"
            else:
                module_tag = f"{self.name}:text_validated"
        else:
            valid = raw_items
            module_tag = f"{self.name}:visual"

        for i, item in enumerate(valid, start=1):
            # Ensure link exists (Lens sometimes only has thumbnail / source)
            if not item.get("link") and item.get("source"):
                item = dict(item)
                item["link"] = item.get("link") or item.get("source")
            results.append(
                OSINTResult.from_serpapi(
                    item,
                    engine=self.engine,
                    query=url,
                    module=module_tag,
                    position=i,
                )
            )

        no_results = bool(data.get("_no_results")) or not raw_items
        attempted.append(
            AttemptedQuery(
                module=self.name,
                engine=self.engine,
                query=url,
                status="empty" if no_results else "ok",
                result_count=len(raw_items),
                filtered_count=len(valid),
                duration_ms=duration,
            )
        )

        if progress:
            progress(
                f"[lens_search] Done — {len(results)} matches "
                f"(raw={len(raw_items)}, kept={len(valid)})"
            )

        return {"results": results, "attempted": attempted}
