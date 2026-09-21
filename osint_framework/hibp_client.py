"""
Have I Been Pwned (HIBP) client.

Endpoint access model (verified against HIBP's published API terms):

===========================================  ==========  ==========================
Endpoint                                     Key needed   Notes
===========================================  ==========  ==========================
/api/v3/breachedaccount/{account}            PAID        32-char hex `hibp-api-key`
/api/v3/pasteaccount/{account}               PAID        32-char hex `hibp-api-key`
/api/v3/breaches                             free        breach catalogue
/api/v3/breach/{name}                        free        single breach detail
/api/v3/dataclasses                          free        data-class vocabulary
===========================================  ==========  ==========================

The account-lookup endpoints are the useful ones for OSINT and they are **not**
free — the cheapest tier is a few dollars a month. This client therefore treats
"no key configured" as an explicit *skip*, never as "no breaches found". That
distinction matters: reporting a clean result because a key was missing is
exactly the false negative `main.run_investigation` guards against.

The transport is injectable so the module can be exercised offline:

    client = HibpClient(api_key="...", session=FakeSession())
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional, Protocol

logger = logging.getLogger("osint.hibp")

API_BASE = "https://haveibeenpwned.com/api/v3"

# HIBP rejects requests without an identifying User-Agent.
DEFAULT_USER_AGENT = (
    "OSINT-Framework (https://github.com/Aduuu0210/OSINT_PROJ_1) breach-check module"
)

# Cheapest published tier is 10 requests/minute. Stay under it by default.
DEFAULT_MIN_INTERVAL = 1.5  # seconds between outgoing calls


class HibpError(Exception):
    """Base error for HIBP operations."""


class HibpAuthError(HibpError):
    """Key missing, invalid, or tier does not permit the endpoint."""


class HibpRateLimitError(HibpError):
    """HTTP 429 — back off and retry."""


class HibpUnavailableError(HibpError):
    """HTTP 5xx / network failure — the lookup did not happen."""


class HibpNotFound(Exception):
    """
    HTTP 404 on an account lookup.

    This is NOT an error: HIBP returns 404 to mean "this account appears in no
    known breaches". Callers must treat it as a genuine negative result.
    """


class HttpLike(Protocol):
    """Minimal surface we need from a session object (requests.Session-shaped)."""

    def get(self, url: str, **kwargs: Any) -> Any: ...


class HibpClient:
    """Thin, rate-limited wrapper over the HIBP v3 REST API."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        session: Optional[HttpLike] = None,
        user_agent: str = DEFAULT_USER_AGENT,
        min_interval: float = DEFAULT_MIN_INTERVAL,
        timeout: float = 20.0,
        max_retries: int = 2,
    ) -> None:
        self.api_key = (
            api_key
            or os.environ.get("HIBP_API_KEY")
            or os.environ.get("HIBP_KEY")
            or ""
        ).strip()
        self.user_agent = user_agent
        self.min_interval = float(min_interval)
        self.timeout = float(timeout)
        self.max_retries = max(0, int(max_retries))

        self._session = session
        self._lock = threading.Lock()
        self._last_call_ts = 0.0
        self._call_count = 0

    # ------------------------------------------------------------------
    # Status helpers
    # ------------------------------------------------------------------

    @property
    def has_key(self) -> bool:
        """True when a key is configured (account lookups are possible)."""
        return bool(self.api_key)

    @property
    def call_count(self) -> int:
        with self._lock:
            return self._call_count

    # ------------------------------------------------------------------
    # Transport
    # ------------------------------------------------------------------

    def _get_session(self) -> HttpLike:
        if self._session is not None:
            return self._session
        try:
            import requests  # type: ignore
        except ImportError as exc:
            raise HibpError(
                "The 'requests' package is required for HIBP lookups. "
                "Run: pip install -r requirements.txt"
            ) from exc
        self._session = requests.Session()
        return self._session

    def _pace(self) -> None:
        with self._lock:
            now = time.monotonic()
            delta = now - self._last_call_ts
            if delta < self.min_interval:
                time.sleep(self.min_interval - delta)
            self._last_call_ts = time.monotonic()
            self._call_count += 1

    def _headers(self, *, authed: bool) -> Dict[str, str]:
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
        }
        if authed:
            if not self.api_key:
                raise HibpAuthError(
                    "No HIBP API key configured. The breachedaccount/pasteaccount "
                    "endpoints are paid — set HIBP_API_KEY or pass api_key=. "
                    "Get a key at https://haveibeenpwned.com/API/Key"
                )
            headers["hibp-api-key"] = self.api_key
        return headers

    def _get(self, path: str, *, authed: bool, params: Optional[Dict[str, Any]] = None) -> Any:
        """GET with retries on 429/5xx. Raises typed errors; returns parsed JSON."""
        url = f"{API_BASE}/{path.lstrip('/')}"
        session = self._get_session()
        last_err: Optional[Exception] = None

        for attempt in range(self.max_retries + 1):
            self._pace()
            try:
                resp = session.get(
                    url,
                    headers=self._headers(authed=authed),
                    params=params or {},
                    timeout=self.timeout,
                )
            except Exception as exc:  # network / DNS / TLS
                last_err = exc
                logger.warning("HIBP %s attempt %s failed: %s", path, attempt + 1, exc)
                if attempt < self.max_retries:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                raise HibpUnavailableError(
                    f"HIBP request to {path} could not complete: {exc}"
                ) from exc

            status = getattr(resp, "status_code", None)

            if status == 200:
                try:
                    return resp.json()
                except Exception as exc:
                    raise HibpError(f"HIBP returned invalid JSON for {path}: {exc}") from exc

            if status == 404:
                raise HibpNotFound(path)

            if status == 401:
                raise HibpAuthError(
                    "HIBP rejected the API key (HTTP 401). Check it at "
                    "https://haveibeenpwned.com/API/Key"
                )
            if status == 403:
                raise HibpAuthError(
                    "HIBP refused the request (HTTP 403). The key's subscription "
                    "tier may not include this endpoint."
                )
            if status == 429:
                last_err = HibpRateLimitError(f"HIBP rate limit hit on {path}")
                if attempt < self.max_retries:
                    time.sleep(2.0 * (attempt + 1))
                    continue
                raise HibpRateLimitError(
                    f"HIBP rate limit exceeded on {path} after "
                    f"{self.max_retries + 1} attempts"
                )
            if status is not None and 500 <= int(status) < 600:
                last_err = HibpUnavailableError(f"HIBP server error {status} on {path}")
                if attempt < self.max_retries:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                raise HibpUnavailableError(
                    f"HIBP returned server error {status} for {path}"
                )

            raise HibpError(f"Unexpected HIBP response {status} for {path}")

        raise HibpUnavailableError(f"HIBP request to {path} failed: {last_err}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def breached_account(
        self, account: str, *, truncate: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Breaches the given email/domain appears in.

        Returns [] when HIBP reports no breaches (HTTP 404) — a real negative.
        Raises HibpAuthError when no key is configured, so callers can record a
        skip rather than a clean result.
        """
        acct = (account or "").strip()
        if not acct:
            return []
        try:
            data = self._get(
                f"breachedaccount/{acct}",
                authed=True,
                params={"truncateResponse": "true" if truncate else "false"},
            )
        except HibpNotFound:
            return []
        return data if isinstance(data, list) else []

    def paste_account(self, account: str) -> List[Dict[str, Any]]:
        """
        Pastes the given email appears in. Same semantics as breached_account.
        """
        acct = (account or "").strip()
        if not acct:
            return []
        try:
            data = self._get(f"pasteaccount/{acct}", authed=True)
        except HibpNotFound:
            return []
        return data if isinstance(data, list) else []

    def breaches(self) -> List[Dict[str, Any]]:
        """
        The public breach catalogue. Free — no API key required.

        Used to enrich account-lookup results and to describe breaches when no
        key is available.
        """
        data = self._get("breaches", authed=False)
        return data if isinstance(data, list) else []
