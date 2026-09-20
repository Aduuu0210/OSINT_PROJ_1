"""
Google News module (engine="google_news").

Scans indexed press releases and media for target mentions.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, List, Optional

from ..models import AttemptedQuery, OSINTResult, filter_valid_hits
from ..serpapi_client import SerpApiClient

logger = logging.getLogger("osint.modules.news_search")

ProgressCb = Optional[Callable[[str], None]]


class NewsSearchModule:
    """Press / media monitoring via Google News."""

    name = "news_search"
    engine = "google_news"

    def __init__(self, client: SerpApiClient) -> None:
        self.client = client

    def build_queries(self, target: str, target_type: str = "auto") -> List[str]:
        t = (target or "").strip().replace('"', "")
        quoted = f'"{t}"'
        queries = [
            quoted,
            f"{quoted} (scam OR fraud OR lawsuit OR arrest OR charged OR investigation)",
            f"{quoted} (breach OR leak OR hack OR ransomware)",
        ]
        if "@" in t:
            local, _, domain = t.partition("@")
            if domain:
                queries.append(f'"{domain}" (breach OR leak OR lawsuit)')
            if local and len(local) > 2:
                queries.append(f'"{local}" "{domain}"')
        # Dedupe
        seen = set()
        out = []
        for q in queries:
            if q.lower() not in seen:
                seen.add(q.lower())
                out.append(q)
        return out

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
            progress(f"[news_search] {len(queries)} Google News queries for '{target}'")

        param_list: List[Dict[str, Any]] = [
            {"engine": self.engine, "q": q, "hl": "en", "gl": "us"} for q in queries
        ]

        def _cb(done: int, total: int, params: Dict[str, Any]) -> None:
            if progress:
                progress(f"[news_search] {done}/{total} — {params.get('q')}")

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

            raw_items = self.client.extract_items(data, keys=["news_results", "organic_results"])
            valid = filter_valid_hits(target, raw_items)

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
            progress(f"[news_search] Done — {len(results)} validated news hits")

        return {"results": results, "attempted": attempted}
