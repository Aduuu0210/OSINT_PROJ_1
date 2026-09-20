"""
Google Maps module (engine="google_maps").

Query phone numbers and addresses to extract business listings,
linked websites, phone numbers, and coordinate markers.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, List, Optional

from ..models import AttemptedQuery, OSINTResult, filter_valid_hits, is_valid_hit
from ..serpapi_client import SerpApiClient

logger = logging.getLogger("osint.modules.maps_search")

ProgressCb = Optional[Callable[[str], None]]


class MapsSearchModule:
    """Geospatial / business intelligence via Google Maps."""

    name = "maps_search"
    engine = "google_maps"

    def __init__(self, client: SerpApiClient) -> None:
        self.client = client

    def build_queries(self, target: str, target_type: str = "auto") -> List[str]:
        t = (target or "").strip()
        queries = [t]

        tt = (target_type or "auto").lower()
        if tt == "phone" or self._looks_phone(t):
            queries.append(f"{t} business")
            queries.append(f"{t} company")
        elif tt == "address" or self._looks_address(t):
            queries.append(t)
        elif tt in {"name", "username"}:
            queries.append(f'"{t}" office')
            queries.append(f'"{t}" headquarters')
        else:
            # email local-part as possible business name
            if "@" in t:
                local = t.split("@", 1)[0].replace(".", " ").replace("_", " ")
                queries.append(local)

        # Dedupe preserve order
        seen = set()
        out = []
        for q in queries:
            qn = q.strip()
            if qn and qn.lower() not in seen:
                seen.add(qn.lower())
                out.append(qn)
        return out

    @staticmethod
    def _looks_phone(t: str) -> bool:
        digits = "".join(c for c in t if c.isdigit())
        return 7 <= len(digits) <= 15 and all(c in "0123456789+()- ./" for c in t)

    @staticmethod
    def _looks_address(t: str) -> bool:
        lower = t.lower()
        return any(
            k in lower
            for k in (
                "street",
                " st",
                "ave",
                "avenue",
                "road",
                " rd",
                "blvd",
                "suite",
                "drive",
                "lane",
                "way",
                ",",
            )
        ) and any(c.isdigit() for c in t)

    def run(
        self,
        target: str,
        *,
        target_type: str = "auto",
        progress: ProgressCb = None,
    ) -> Dict[str, Any]:
        queries = self.build_queries(target, target_type=target_type)
        results: List[OSINTResult] = []
        attempted: List[AttemptedQuery] = []

        if progress:
            progress(f"[maps_search] {len(queries)} Google Maps queries for '{target}'")

        param_list: List[Dict[str, Any]] = [
            {"engine": self.engine, "q": q, "type": "search"} for q in queries
        ]

        def _cb(done: int, total: int, params: Dict[str, Any]) -> None:
            if progress:
                progress(f"[maps_search] {done}/{total} — {params.get('q')}")

        batch = self.client.batch_search(param_list, progress_callback=_cb)

        for params, data, err in batch:
            query = str(params.get("q") or "")
            t0 = time.monotonic()

            if err:
                attempted.append(
                    AttemptedQuery(
                        module=self.name,
                        engine=self.engine,
                        query=query,
                        status="error",
                        error_message=str(err),
                    )
                )
                continue

            raw_items = self.client.extract_items(
                data, keys=["local_results", "place_results"]
            )

            # Maps results often put the match in title/address/phone —
            # still enforce is_valid_hit against the original target.
            valid = []
            for item in raw_items:
                if is_valid_hit(target, item):
                    valid.append(item)
                else:
                    # Secondary: if the query itself was the phone/address and
                    # Maps returned a structured place, accept when phone or
                    # address field is present (high confidence structured hit).
                    if item.get("phone") or item.get("address") or item.get("gps_coordinates"):
                        # Require at least one field containing a target token
                        if is_valid_hit(target, item):
                            valid.append(item)
                        elif target_type in {"phone", "address"} or self._looks_phone(target) or self._looks_address(target):
                            # Structured place result for a phone/address query is high-signal
                            valid.append(item)

            for i, item in enumerate(valid, start=1):
                results.append(
                    OSINTResult.from_serpapi(
                        item,
                        engine=self.engine,
                        query=query,
                        module=self.name,
                        position=i,
                    )
                )

            no_results = bool(data.get("_no_results")) or not raw_items
            attempted.append(
                AttemptedQuery(
                    module=self.name,
                    engine=self.engine,
                    query=query,
                    status="empty" if no_results else "ok",
                    result_count=len(raw_items),
                    filtered_count=len(valid),
                    duration_ms=(time.monotonic() - t0) * 1000.0,
                )
            )

        if progress:
            progress(f"[maps_search] Done — {len(results)} place hits")

        return {"results": results, "attempted": attempted}
