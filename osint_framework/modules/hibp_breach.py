"""
Have I Been Pwned breach-exposure module (engine="hibp").

Complements the Google dorking modules: where `web_dorks` finds what is
*publicly indexed*, this module answers the narrower and much stronger question
"does this exact account appear in a known data breach?".

Two facts shape the design:

1. **The account-lookup endpoints are paid.** `breachedaccount` and
   `pasteaccount` require a `hibp-api-key`. Without one the check cannot be
   performed at all, so this module records an *error* — never a silent "no
   breaches found". `main.run_investigation` turns that into an INCOMPLETE
   report rather than a clean one.

2. **HTTP 404 means "no breaches", not "failure".** HIBP signals a genuine
   negative with 404. That is recorded as a successful, empty lookup.

Because the lookup is keyed by the exact account, results are inherently
exact-match. They are still passed through `filter_valid_hits` so the
anti-false-positive contract holds uniformly across every module.

This module is **off by default** — it needs its own paid key, and it is the one
module that leaves the SerpApi-only collection path.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import quote

from ..hibp_client import (
    HibpAuthError,
    HibpClient,
    HibpError,
    HibpRateLimitError,
    HibpUnavailableError,
)
from ..models import AttemptedQuery, OSINTResult, filter_valid_hits

logger = logging.getLogger("osint.modules.hibp_breach")

ProgressCb = Optional[Callable[[str], None]]

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def _is_email(value: str) -> bool:
    return bool(EMAIL_RE.fullmatch((value or "").strip()))


def _domain_of(email: str) -> str:
    return (email or "").strip().split("@", 1)[-1].lower() if "@" in email else ""


class HibpBreachModule:
    """Breach and paste exposure via Have I Been Pwned."""

    name = "hibp_breach"
    engine = "hibp"

    def __init__(self, client: Optional[HibpClient] = None, **kwargs: Any) -> None:
        self.client = client if client is not None else HibpClient(**kwargs)

    # ------------------------------------------------------------------
    # Query planning
    # ------------------------------------------------------------------

    def build_queries(self, target: str, target_type: str = "auto") -> List[Dict[str, str]]:
        """
        Return the accounts to look up, as ``{"kind": ..., "account": ...}``.

        Only real email addresses and domains are queried — guessing addresses
        from a bare username would manufacture false positives, which this
        framework exists to prevent.
        """
        t = (target or "").strip()
        out: List[Dict[str, str]] = []
        seen = set()

        def add(kind: str, account: str) -> None:
            account = account.strip().lower()
            if account and (kind, account) not in seen:
                seen.add((kind, account))
                out.append({"kind": kind, "account": account})

        if _is_email(t):
            add("breaches", t)
            add("pastes", t)
            # Domain-level exposure: same endpoint, domain as the account.
            add("breaches", _domain_of(t))
        elif re.fullmatch(r"[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", t):
            # Bare domain
            add("breaches", t.lower())

        return out

    # ------------------------------------------------------------------
    # Result shaping
    # ------------------------------------------------------------------

    @staticmethod
    def _shape_breach(account: str, breach: Dict[str, Any], kind: str) -> Dict[str, Any]:
        """Normalise a HIBP breach/paste record into a dict the models accept."""
        name = str(breach.get("Name") or breach.get("Title") or "unknown")
        title_field = str(breach.get("Title") or name)
        domain = str(breach.get("Domain") or "")
        date = str(breach.get("BreachDate") or breach.get("AddedDate") or "")
        pwn_count = breach.get("PwnCount")
        data_classes = breach.get("DataClasses") or []
        if isinstance(data_classes, list):
            classes_txt = ", ".join(str(c) for c in data_classes[:12])
        else:
            classes_txt = str(data_classes)

        if kind == "pastes":
            source = str(breach.get("Source") or "paste")
            link = f"https://haveibeenpwned.com/PasteSearch#pastes"
            snippet = (
                f"{account} appears in a {source} paste"
                + (f" titled '{breach.get('Title')}'" if breach.get("Title") else "")
                + (f" — {classes_txt}" if classes_txt else "")
            )
        else:
            link = f"https://haveibeenpwned.com/breach/{quote(name, safe='')}"
            verified = breach.get("IsVerified")
            flags = []
            if breach.get("IsSensitive"):
                flags.append("sensitive")
            if breach.get("IsRetired"):
                flags.append("retired")
            if breach.get("IsSpamList"):
                flags.append("spam-list")
            if verified is False:
                flags.append("unverified")
            snippet = (
                f"{account} exposed in the {title_field} breach"
                + (f" ({domain})" if domain else "")
                + (f" on {date}" if date else "")
                + (f" — {pwn_count:,} accounts" if isinstance(pwn_count, int) else "")
                + (f" — data classes: {classes_txt}" if classes_txt else "")
                + (f" [{', '.join(flags)}]" if flags else "")
            )

        return {
            "title": f"HIBP: {title_field}" + (" (paste)" if kind == "pastes" else ""),
            "link": link,
            "snippet": snippet,
            "source": domain or "haveibeenpwned.com",
            "date": date,
            "name": name,
            # Carry structured detail through to exports via OSINTResult.raw.
            "account": account,
            "kind": kind,
            "pwn_count": pwn_count,
            "data_classes": data_classes,
            "is_verified": breach.get("IsVerified"),
            "is_sensitive": breach.get("IsSensitive"),
        }

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def run(
        self,
        target: str,
        *,
        target_type: str = "auto",
        progress: ProgressCb = None,
    ) -> Dict[str, Any]:
        """
        Look the target up on HIBP.

        Returns ``{"results": List[OSINTResult], "attempted": List[AttemptedQuery]}``.
        """
        results: List[OSINTResult] = []
        attempted: List[AttemptedQuery] = []

        specs = self.build_queries(target, target_type=target_type)

        if not specs:
            msg = (
                f"Skipped: '{target}' is not an email address or domain. "
                "HIBP account lookups need an exact email (or a domain)."
            )
            if progress:
                progress(f"[hibp_breach] {msg}")
            attempted.append(
                AttemptedQuery(
                    module=self.name,
                    engine=self.engine,
                    query=target or "",
                    status="skipped",
                    error_message=msg,
                )
            )
            return {"results": results, "attempted": attempted}

        if not self.client.has_key:
            msg = (
                "No HIBP API key configured — the breachedaccount/pasteaccount "
                "endpoints are paid, so the breach check was NOT performed. "
                "Set HIBP_API_KEY (https://haveibeenpwned.com/API/Key). "
                "This is not a 'no breaches' result."
            )
            logger.warning("[hibp_breach] %s", msg)
            if progress:
                progress(f"[hibp_breach] {msg}")
            for spec in specs:
                attempted.append(
                    AttemptedQuery(
                        module=self.name,
                        engine=self.engine,
                        query=f"{spec['kind']}:{spec['account']}",
                        status="error",
                        error_message=msg,
                    )
                )
            return {"results": results, "attempted": attempted}

        if progress:
            progress(f"[hibp_breach] {len(specs)} HIBP lookups for '{target}'")

        for i, spec in enumerate(specs, start=1):
            kind, account = spec["kind"], spec["account"]
            label = f"{kind}:{account}"
            t0 = time.monotonic()
            if progress:
                progress(f"[hibp_breach] {i}/{len(specs)} — {label}")

            try:
                if kind == "pastes":
                    records = self.client.paste_account(account)
                else:
                    records = self.client.breached_account(account)
            except HibpAuthError as exc:
                attempted.append(
                    AttemptedQuery(
                        module=self.name, engine=self.engine, query=label,
                        status="error", error_message=str(exc),
                        duration_ms=(time.monotonic() - t0) * 1000.0,
                    )
                )
                if progress:
                    progress(f"[hibp_breach] AUTH FAILED on {label}: {exc}")
                # No point retrying every spec with a rejected key.
                for rest in specs[i:]:
                    attempted.append(
                        AttemptedQuery(
                            module=self.name, engine=self.engine,
                            query=f"{rest['kind']}:{rest['account']}",
                            status="error", error_message=str(exc),
                        )
                    )
                break
            except (HibpRateLimitError, HibpUnavailableError, HibpError) as exc:
                attempted.append(
                    AttemptedQuery(
                        module=self.name, engine=self.engine, query=label,
                        status="error", error_message=str(exc),
                        duration_ms=(time.monotonic() - t0) * 1000.0,
                    )
                )
                if progress:
                    progress(f"[hibp_breach] FAILED {label}: {exc}")
                continue

            shaped = [self._shape_breach(account, b, kind) for b in records]
            # Defence in depth: the account is embedded in every snippet, so a
            # well-formed response always validates. Anything that does not is
            # dropped rather than trusted.
            valid = filter_valid_hits(account, shaped)

            for pos, item in enumerate(valid, start=1):
                results.append(
                    OSINTResult.from_serpapi(
                        item,
                        engine=self.engine,
                        query=label,
                        module=self.name,
                        position=pos,
                    )
                )

            attempted.append(
                AttemptedQuery(
                    module=self.name,
                    engine=self.engine,
                    query=label,
                    status="ok" if records else "empty",
                    result_count=len(shaped),
                    filtered_count=len(valid),
                    duration_ms=(time.monotonic() - t0) * 1000.0,
                )
            )

        if progress:
            progress(
                f"[hibp_breach] Done — {len(results)} confirmed breach/paste exposures"
            )

        return {"results": results, "attempted": attempted}
