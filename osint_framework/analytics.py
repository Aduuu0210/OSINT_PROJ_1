"""
AI analytics layer: entity extraction (NER via regex) and dynamic threat scoring.
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

from .models import (
    ExtractedEntity,
    InvestigationReport,
    OSINTResult,
    RiskLevel,
    ThreatAssessment,
)

logger = logging.getLogger("osint.analytics")


# ---------------------------------------------------------------------------
# Regex library for lightweight NER over SerpApi snippets
# ---------------------------------------------------------------------------

# Emails
EMAIL_RE = re.compile(
    r"\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b"
)

# Phones — various international-ish shapes (kept deliberately broad, then cleaned)
PHONE_RE = re.compile(
    r"(?:(?:\+|00)\d{1,3}[\s\-.]*)?(?:\(?\d{2,4}\)?[\s\-.]*)?\d{3,4}[\s\-.]+\d{3,4}"
    r"|\b\d{3}[\s\-.]?\d{3}[\s\-.]?\d{4}\b"
    r"|\b\+?\d{10,15}\b"
)

# IPv4
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# BTC (Legacy 1/3 + Bech32 bc1)
BTC_RE = re.compile(
    r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,90})\b"
)

# ETH / EVM
ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

# XMR (Monero standard addresses start with 4, integrated with 4/8)
XMR_RE = re.compile(r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")

# Social handles
SOCIAL_HANDLE_RE = re.compile(r"(?<![a-zA-Z0-9])@([A-Za-z0-9_]{2,30})\b")

# Common social profile URL patterns
SOCIAL_URL_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("twitter", re.compile(r"https?://(?:www\.)?(?:twitter|x)\.com/([A-Za-z0-9_]+)", re.I)),
    ("linkedin", re.compile(r"https?://(?:www\.)?linkedin\.com/in/([A-Za-z0-9\-_%]+)", re.I)),
    ("github", re.compile(r"https?://(?:www\.)?github\.com/([A-Za-z0-9\-]+)", re.I)),
    ("instagram", re.compile(r"https?://(?:www\.)?instagram\.com/([A-Za-z0-9._]+)", re.I)),
    ("facebook", re.compile(r"https?://(?:www\.)?facebook\.com/([A-Za-z0-9.]+)", re.I)),
    ("telegram", re.compile(r"https?://(?:t\.me|telegram\.me)/([A-Za-z0-9_]+)", re.I)),
    ("reddit", re.compile(r"https?://(?:www\.)?reddit\.com/user/([A-Za-z0-9_\-]+)", re.I)),
    ("tiktok", re.compile(r"https?://(?:www\.)?tiktok\.com/@([A-Za-z0-9._]+)", re.I)),
    ("youtube", re.compile(r"https?://(?:www\.)?youtube\.com/(?:@|channel/|user/)([A-Za-z0-9_\-]+)", re.I)),
]


# High-risk host / keyword indicators for scoring
PASTE_HOSTS = {
    "pastebin.com",
    "paste.ee",
    "ghostbin.com",
    "dpaste.com",
    "hastebin.com",
    "rentry.co",
    "pastebin.pl",
    "justpaste.it",
    "controlc.com",
    "ideone.com",
    "codepad.org",
}

SCAM_HOSTS = {
    "scamwatcher.com",
    "scamadviser.com",
    "scamdoc.com",
    "scamcallfighters.com",
    "whosenumber.info",
    "whocallsme.com",
    "shouldianswer.com",
    "800notes.com",
    "whycall.me",
    "scam-detector.com",
    "bbb.org",
    "ripoffreport.com",
    "sitejabber.com",
    "trustpilot.com",
    "complaintboard.com",
    "consumeraffairs.com",
}

BREACH_KEYWORDS = {
    "leak",
    "breach",
    "dump",
    "combo list",
    "combolist",
    "stealer",
    "credential",
    "database leak",
    "data breach",
    "exposed password",
    "rockyou",
    "collection #",
    "dehashed",
    "have i been pwned",
    "hibp",
    "infostealer",
    "redline",
    "racoon",
    "vidar",
}

DARK_KEYWORDS = {
    "dark web",
    "darkweb",
    "tor ",
    ".onion",
    "ransomware",
    "carding",
    "cvv",
    "fullz",
    "ddos-for-hire",
}


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).netloc or "").lower().lstrip("www.")
    except Exception:
        return ""


def _clean_phone(raw: str) -> Optional[str]:
    digits = re.sub(r"\D", "", raw or "")
    if len(digits) < 7 or len(digits) > 15:
        return None
    # Filter out obvious non-phones (years, IDs embedded in text)
    if digits.startswith("20") and len(digits) == 8:  # years like 20240101
        return None
    return digits


def _is_plausible_btc(addr: str) -> bool:
    # Very light sanity: length bounds already in regex; reject pure hex ETH-like
    if addr.startswith("0x"):
        return False
    return 26 <= len(addr) <= 90


# ---------------------------------------------------------------------------
# Entity extraction
# ---------------------------------------------------------------------------

class EntityExtractor:
    """Regex-driven NER over titles, snippets, and URLs."""

    def __init__(self, exclude_values: Optional[Set[str]] = None) -> None:
        # Values to skip (usually the original target itself)
        self.exclude = {v.lower() for v in (exclude_values or set()) if v}

    def extract_from_text(
        self,
        text: str,
        *,
        source_link: str = "",
    ) -> List[ExtractedEntity]:
        if not text:
            return []
        found: List[ExtractedEntity] = []
        seen: Set[Tuple[str, str]] = set()

        def _add(etype: str, value: str, conf: float = 0.85) -> None:
            value = (value or "").strip()
            if not value:
                return
            key = (etype, value.lower())
            if key in seen:
                return
            if value.lower() in self.exclude:
                return
            seen.add(key)
            # Short context window
            ctx = text
            idx = text.lower().find(value.lower())
            if idx >= 0:
                start = max(0, idx - 40)
                end = min(len(text), idx + len(value) + 40)
                ctx = text[start:end].replace("\n", " ")
            found.append(
                ExtractedEntity(
                    entity_type=etype,
                    value=value,
                    context=ctx,
                    source_link=source_link,
                    confidence=conf,
                )
            )

        for m in EMAIL_RE.finditer(text):
            _add("email", m.group(1), 0.95)

        for m in PHONE_RE.finditer(text):
            cleaned = _clean_phone(m.group(0))
            if cleaned:
                _add("phone", cleaned, 0.75)

        for m in IPV4_RE.finditer(text):
            ip = m.group(0)
            # Skip 0.0.0.0 / 255.255.255.255 noise
            if ip not in ("0.0.0.0", "255.255.255.255", "127.0.0.1"):
                _add("ip", ip, 0.8)

        for m in BTC_RE.finditer(text):
            addr = m.group(0)
            if _is_plausible_btc(addr):
                _add("btc", addr, 0.9)

        for m in ETH_RE.finditer(text):
            _add("eth", m.group(0), 0.92)

        for m in XMR_RE.finditer(text):
            _add("xmr", m.group(0), 0.9)

        for m in SOCIAL_HANDLE_RE.finditer(text):
            handle = m.group(1)
            if handle.lower() not in {"http", "https", "www"}:
                _add("social", f"@{handle}", 0.7)

        for platform, pattern in SOCIAL_URL_PATTERNS:
            for m in pattern.finditer(text):
                _add("social", f"{platform}:@{m.group(1)}", 0.9)

        return found

    def extract_from_results(
        self,
        results: Iterable[OSINTResult],
    ) -> List[ExtractedEntity]:
        all_entities: List[ExtractedEntity] = []
        seen: Set[Tuple[str, str]] = set()
        for r in results:
            blob = " ".join(
                x for x in [r.title, r.snippet, r.link, r.phone, r.address] if x
            )
            # Also harvest structured fields directly
            if r.phone:
                blob += f" {r.phone}"
            for ent in self.extract_from_text(blob, source_link=r.link):
                key = (ent.entity_type, ent.value.lower())
                if key in seen:
                    continue
                seen.add(key)
                all_entities.append(ent)

            # Social URLs from the link itself
            for platform, pattern in SOCIAL_URL_PATTERNS:
                m = pattern.search(r.link or "")
                if m:
                    val = f"{platform}:@{m.group(1)}"
                    key = ("social", val.lower())
                    if key not in seen:
                        seen.add(key)
                        all_entities.append(
                            ExtractedEntity(
                                entity_type="social",
                                value=val,
                                context=r.title,
                                source_link=r.link,
                                confidence=0.95,
                            )
                        )
        return all_entities


# ---------------------------------------------------------------------------
# Threat scoring
# ---------------------------------------------------------------------------

class ThreatScorer:
    """
    Dynamic 0-100 risk score.

    Signals (additive, capped at 100):
      - Presence on paste sites            +25 each host (cap 40)
      - Scam-board / complaint sites       +20 each host (cap 40)
      - Exposed PDFs / docs                +10 each (cap 20)
      - Breach / dump keywords             +15 (once) +5 per extra (cap 30)
      - Dark-web keywords                  +20
      - Crypto wallets found               +10
      - Multiple phones / emails pivoted   +5
      - High raw hit volume                +5 / +10
    """

    def score(
        self,
        results: List[OSINTResult],
        entities: Optional[List[ExtractedEntity]] = None,
        target: str = "",
    ) -> ThreatAssessment:
        entities = entities or []
        factors: List[str] = []
        score = 0

        hosts = [_host_of(r.link) for r in results if r.link]
        host_counter = Counter(h for h in hosts if h)

        # Paste sites
        paste_hits = {h for h in host_counter if any(p in h for p in PASTE_HOSTS)}
        if paste_hits:
            pts = min(40, 25 * len(paste_hits))
            score += pts
            factors.append(
                f"Target referenced on paste / dump sites ({', '.join(sorted(paste_hits))}): +{pts}"
            )

        # Scam boards
        scam_hits = {h for h in host_counter if any(s in h for s in SCAM_HOSTS)}
        if scam_hits:
            pts = min(40, 20 * len(scam_hits))
            score += pts
            factors.append(
                f"Target appears on scam / complaint boards ({', '.join(sorted(scam_hits))}): +{pts}"
            )

        # Exposed documents (PDF / doc / xls / csv)
        doc_exts = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".txt", ".sql")
        doc_hits = [
            r
            for r in results
            if (r.link or "").lower().endswith(doc_exts)
            or any(ext in (r.link or "").lower() for ext in doc_exts)
            or "filetype:pdf" in (r.query or "").lower()
        ]
        # Unique by link
        doc_links = {r.link for r in doc_hits if r.link}
        if doc_links:
            pts = min(20, 10 * len(doc_links))
            score += pts
            factors.append(f"Exposed documents indexed ({len(doc_links)}): +{pts}")

        # Keyword sweeps across title+snippet
        corpus = " ".join(
            f"{r.title} {r.snippet}".lower() for r in results
        )
        breach_hits = [k for k in BREACH_KEYWORDS if k in corpus]
        if breach_hits:
            pts = min(30, 15 + 5 * (len(breach_hits) - 1))
            score += pts
            factors.append(
                f"Breach / credential-leak language detected ({', '.join(breach_hits[:5])}): +{pts}"
            )

        dark_hits = [k for k in DARK_KEYWORDS if k in corpus]
        if dark_hits:
            pts = 20
            score += pts
            factors.append(
                f"Dark-web / criminal-market language detected ({', '.join(dark_hits[:4])}): +{pts}"
            )

        # Crypto wallets
        wallets = [e for e in entities if e.entity_type in {"btc", "eth", "xmr"}]
        if wallets:
            pts = min(20, 10 + 5 * (len(wallets) - 1))
            score += pts
            factors.append(f"Cryptocurrency wallet addresses extracted ({len(wallets)}): +{pts}")

        # Pivoted contact surface
        emails = {e.value.lower() for e in entities if e.entity_type == "email"}
        phones = {e.value for e in entities if e.entity_type == "phone"}
        if target:
            emails.discard(target.lower())
        if len(emails) + len(phones) >= 3:
            score += 5
            factors.append(
                f"Expanded contact surface (emails={len(emails)}, phones={len(phones)}): +5"
            )

        # Volume signal
        n = len(results)
        if n >= 25:
            score += 10
            factors.append(f"High public footprint ({n} validated hits): +10")
        elif n >= 10:
            score += 5
            factors.append(f"Moderate public footprint ({n} validated hits): +5")
        elif n == 0:
            factors.append("No validated public hits — residual risk only.")

        score = max(0, min(100, int(score)))
        level = self._level_for(score)
        summary = self._summarize(score, level, factors, target)

        return ThreatAssessment(
            score=score,
            level=level,
            factors=factors,
            summary=summary,
        )

    @staticmethod
    def _level_for(score: int) -> RiskLevel:
        if score >= 75:
            return RiskLevel.CRITICAL
        if score >= 50:
            return RiskLevel.HIGH
        if score >= 25:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    @staticmethod
    def _summarize(
        score: int,
        level: RiskLevel,
        factors: List[str],
        target: str,
    ) -> str:
        if score == 0:
            return (
                f"No elevated risk indicators were observed for '{target}'. "
                "This does not guarantee safety — only that open-source signals "
                "in the scanned engines were clean."
            )
        top = "; ".join(factors[:3]) if factors else "multiple weak signals"
        return (
            f"Threat score {score}/100 ({level.value}) for '{target}'. "
            f"Primary drivers: {top}."
        )


def analyze_report(report: InvestigationReport) -> InvestigationReport:
    """
    In-place enrichment: run NER + threat scoring over the investigation report.
    """
    exclude = {report.target}
    extractor = EntityExtractor(exclude_values=exclude)
    results = report.deduplicated_results()
    entities = extractor.extract_from_results(results)
    report.entities = entities

    scorer = ThreatScorer()
    report.threat = scorer.score(results, entities, target=report.target)
    return report


def detect_target_type(target: str) -> str:
    """Heuristic target classification for module routing."""
    t = (target or "").strip()
    if not t:
        return "unknown"
    if re.match(r"^https?://.+\.(jpg|jpeg|png|gif|webp|bmp)(\?.*)?$", t, re.I):
        return "image"
    if EMAIL_RE.fullmatch(t):
        return "email"
    digits = re.sub(r"\D", "", t)
    if len(digits) >= 7 and len(digits) <= 15 and re.match(r"^[\d\s\-+().]+$", t):
        return "phone"
    if t.startswith("http://") or t.startswith("https://"):
        return "url"
    if t.startswith("@") or re.fullmatch(r"[A-Za-z0-9_.]{2,32}", t):
        # Could be username or plain name — treat short tokens as username
        if " " not in t and len(t) <= 32:
            return "username"
    if re.search(r"\d+", t) and any(
        k in t.lower() for k in ("st", "ave", "rd", "street", "road", "blvd", "suite", ",")
    ):
        return "address"
    return "name"
