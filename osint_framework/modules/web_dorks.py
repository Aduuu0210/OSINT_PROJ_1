"""
Google web dorks module (engine="google").

Uses strict literal double-quoting and path-restricted URI filters to cut noise.
Every hit is gated through ``is_valid_hit`` before retention.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, List, Optional

from ..models import AttemptedQuery, OSINTResult, filter_valid_hits
from ..serpapi_client import SerpApiClient, SerpApiError

logger = logging.getLogger("osint.modules.web_dorks")

ProgressCb = Optional[Callable[[str], None]]


def _q(target: str) -> str:
    """Strict literal quoting — escapes embedded double-quotes."""
    cleaned = (target or "").strip().replace('"', "")
    return f'"{cleaned}"'


class WebDorksModule:
    """Multi-dork Google search designed to eliminate false positives."""

    name = "web_dorks"
    engine = "google"

    # (label, query_template) — `{t}` is replaced with the quoted target
    DORK_TEMPLATES = [
        # Identity surface
        ("general_literal", '{t}'),
        ("linkedin_profile", 'site:linkedin.com/in/ {t}'),
        ("linkedin_any", 'site:linkedin.com {t}'),
        ("twitter_x", 'site:twitter.com OR site:x.com {t}'),
        ("facebook", 'site:facebook.com {t}'),
        ("instagram", 'site:instagram.com {t}'),
        ("github", 'site:github.com {t}'),
        ("reddit", 'site:reddit.com {t}'),
        # Breach / paste / scam
        ("pastebin", 'site:pastebin.com {t}'),
        ("paste_sites", 'site:pastebin.com OR site:paste.ee OR site:rentry.co OR site:justpaste.it {t}'),
        ("scam_boards", 'site:scamwatcher.com OR site:scamadviser.com OR site:ripoffreport.com OR site:800notes.com {t}'),
        ("bbb_complaints", 'site:bbb.org {t}'),
        # Documents
        ("exposed_pdf", 'filetype:pdf {t}'),
        ("exposed_docs", 'filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx OR filetype:csv {t}'),
        # Contact pivots
        ("email_intext", 'intext:{t} (email OR contact OR phone)'),
        ("whois_mentions", 'site:whois.com OR site:whoxy.com OR site:viewdns.info {t}'),
    ]

    # Extra dorks when the target looks like an email
    EMAIL_DORKS = [
        ("email_breach_lang", '{t} (breach OR leak OR dump OR password OR combo)'),
        ("email_site_docs", '{t} filetype:pdf OR filetype:txt OR filetype:csv'),
    ]

    # Extra dorks for phone numbers
    PHONE_DORKS = [
        ("phone_reverse", '{t} (owner OR reverse OR lookup OR spam OR scam)'),
        ("phone_boards", 'site:800notes.com OR site:whocallsme.com OR site:shouldianswer.com {t}'),
    ]

    def __init__(self, client: SerpApiClient) -> None:
        self.client = client

    def build_queries(self, target: str, target_type: str = "auto") -> List[Dict[str, str]]:
        quoted = _q(target)
        templates = list(self.DORK_TEMPLATES)
        tt = (target_type or "auto").lower()
        if tt == "email" or "@" in target:
            templates.extend(self.EMAIL_DORKS)
        if tt == "phone":
            templates.extend(self.PHONE_DORKS)

        queries: List[Dict[str, str]] = []
        for label, tmpl in templates:
            q = tmpl.replace("{t}", quoted)
            queries.append({"label": label, "q": q})
        return queries

    def run(
        self,
        target: str,
        *,
        target_type: str = "auto",
        num_per_query: int = 10,
        progress: ProgressCb = None,
    ) -> Dict[str, Any]:
        """
        Execute all dorks (concurrently via the shared client).

        Returns ``{"results": List[OSINTResult], "attempted": List[AttemptedQuery]}``.
        """
        specs = self.build_queries(target, target_type=target_type)
        param_list: List[Dict[str, Any]] = []
        for spec in specs:
            param_list.append(
                {
                    "engine": self.engine,
                    "q": spec["q"],
                    "num": num_per_query,
                    "_label": spec["label"],
                }
            )

        def _cb(done: int, total: int, params: Dict[str, Any]) -> None:
            if progress:
                progress(
                    f"[web_dorks] {done}/{total} — {params.get('_label', params.get('q', ''))}"
                )

        if progress:
            progress(f"[web_dorks] Launching {len(param_list)} Google dorks for '{target}'")

        batch = self.client.batch_search(param_list, progress_callback=_cb)

        results: List[OSINTResult] = []
        attempted: List[AttemptedQuery] = []

        for params, data, err in batch:
            label = str(params.get("_label") or "dork")
            query = str(params.get("q") or "")
            t0 = time.monotonic()  # duration already spent; store 0-ish
            if err:
                attempted.append(
                    AttemptedQuery(
                        module=self.name,
                        engine=self.engine,
                        query=query,
                        status="error",
                        result_count=0,
                        filtered_count=0,
                        error_message=str(err),
                    )
                )
                continue

            raw_items = self.client.extract_items(
                data, keys=["organic_results", "images_results"]
            )
            # Anti-FP gate
            valid = filter_valid_hits(target, raw_items)
            for i, item in enumerate(valid, start=1):
                results.append(
                    OSINTResult.from_serpapi(
                        item,
                        engine=self.engine,
                        query=query,
                        module=f"{self.name}:{label}",
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
            progress(
                f"[web_dorks] Done — {len(results)} validated hits across "
                f"{len(attempted)} queries"
            )

        return {"results": results, "attempted": attempted}
