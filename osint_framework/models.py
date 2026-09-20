"""
Data models and the anti-false-positive filter for the OSINT framework.

Every SerpApi hit MUST pass ``is_valid_hit`` before it is retained. This is the
single most important guardrail against noisy / irrelevant results.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import unquote, urlparse


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
    UNKNOWN = "Unknown"


class EngineType(str, Enum):
    GOOGLE = "google"
    GOOGLE_LENS = "google_lens"
    GOOGLE_MAPS = "google_maps"
    GOOGLE_NEWS = "google_news"


# ---------------------------------------------------------------------------
# Anti-false-positive filter (CRITICAL)
# ---------------------------------------------------------------------------

def _normalize(text: str) -> str:
    """Lowercase, collapse whitespace, strip punctuation noise for comparison."""
    if not text:
        return ""
    text = unquote(str(text)).lower()
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _target_variants(target: str) -> List[str]:
    """
    Build comparison variants of the target string.

    Handles emails (local + domain parts), phone numbers (digit-only), and
    plain names / handles.
    """
    t = (target or "").strip()
    if not t:
        return []

    variants = {_normalize(t)}

    # Email: also match local-part and domain independently when full email present
    if "@" in t:
        local, _, domain = t.partition("@")
        if local:
            variants.add(_normalize(local))
        if domain:
            variants.add(_normalize(domain))

    # Phone: digit-only and last-10 form
    digits = re.sub(r"\D", "", t)
    if len(digits) >= 7:
        variants.add(digits)
        variants.add(digits[-10:])  # national number without country code
        # Common formatted shapes
        if len(digits) >= 10:
            n = digits[-10:]
            variants.add(f"({n[:3]}) {n[3:6]}-{n[6:]}")
            variants.add(f"{n[:3]}-{n[3:6]}-{n[6:]}")
            variants.add(f"{n[:3]}.{n[3:6]}.{n[6:]}")

    # Username / handle without leading @
    if t.startswith("@"):
        variants.add(_normalize(t[1:]))

    # Remove empty
    return [v for v in variants if v]


def is_valid_hit(target: str, result_dict: Dict[str, Any]) -> bool:
    """
    Strict anti-false-positive gate.

    Returns True **only** when the exact target string (case-insensitive), or a
    high-confidence variant of it, appears in the result's title, snippet,
    link/URL, or other common SerpApi text fields.

    Any result that fails this check MUST be discarded.
    """
    if not target or not isinstance(result_dict, dict):
        return False

    variants = _target_variants(target)
    if not variants:
        return False

    # Collect all searchable text fields from a SerpApi organic / maps / news / lens result
    fields_to_scan = [
        "title",
        "snippet",
        "snippet_highlighted_words",
        "link",
        "url",
        "displayed_link",
        "source",
        "description",
        "address",
        "phone",
        "website",
        "name",
        "query",
        "thumbnail",
        "favicon",
        "rich_snippet",
    ]

    chunks: List[str] = []
    for key in fields_to_scan:
        val = result_dict.get(key)
        if val is None:
            continue
        if isinstance(val, list):
            chunks.extend(str(x) for x in val if x)
        elif isinstance(val, dict):
            # Flatten one level (e.g. rich_snippet)
            for sub in val.values():
                if isinstance(sub, (str, int, float)):
                    chunks.append(str(sub))
                elif isinstance(sub, list):
                    chunks.extend(str(x) for x in sub if x)
        else:
            chunks.append(str(val))

    # Also scan nested gps_coordinates / extensions if present
    for nested_key in ("gps_coordinates", "extensions", "about_this_result", "detected_extensions"):
        nested = result_dict.get(nested_key)
        if isinstance(nested, dict):
            for v in nested.values():
                if v is not None:
                    chunks.append(str(v))
        elif isinstance(nested, list):
            chunks.extend(str(x) for x in nested if x)

    haystack = _normalize(" ".join(chunks))
    if not haystack:
        return False

    for variant in variants:
        # Exact substring match (case-insensitive via normalize)
        if variant in haystack:
            return True
        # Word-boundary aware match for short alphanumeric tokens to avoid
        # partial collisions (e.g. "ann" inside "annual")
        if len(variant) <= 3 and variant.isalnum():
            if re.search(rf"(?<![a-z0-9]){re.escape(variant)}(?![a-z0-9])", haystack):
                return True
        elif variant in haystack:
            return True

    return False


def filter_valid_hits(target: str, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Apply ``is_valid_hit`` across a list; preserve original order."""
    if not results:
        return []
    return [r for r in results if is_valid_hit(target, r)]


# ---------------------------------------------------------------------------
# Core data classes
# ---------------------------------------------------------------------------

@dataclass
class OSINTResult:
    """A single validated intelligence hit."""

    title: str = ""
    link: str = ""
    snippet: str = ""
    source: str = ""
    engine: str = EngineType.GOOGLE.value
    query: str = ""
    module: str = ""
    position: int = 0
    raw: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    # Optional enrichment
    phone: str = ""
    address: str = ""
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    rating: Optional[float] = None
    date: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Keep raw compact in exports; callers can drop it
        return d

    @classmethod
    def from_serpapi(
        cls,
        item: Dict[str, Any],
        *,
        engine: str,
        query: str,
        module: str,
        position: int = 0,
    ) -> "OSINTResult":
        """Hydrate from a SerpApi organic / maps / news / lens dict."""
        gps = item.get("gps_coordinates") or {}
        lat = gps.get("latitude") if isinstance(gps, dict) else None
        lng = gps.get("longitude") if isinstance(gps, dict) else None

        link = (
            item.get("link")
            or item.get("url")
            or item.get("website")
            or item.get("thumbnail")
            or ""
        )
        title = item.get("title") or item.get("name") or item.get("source") or ""
        snippet = (
            item.get("snippet")
            or item.get("description")
            or item.get("address")
            or ""
        )
        source = item.get("source") or item.get("displayed_link") or ""
        if not source and link:
            try:
                source = urlparse(link).netloc
            except Exception:
                source = ""

        phone = str(item.get("phone") or "")
        address = str(item.get("address") or "")
        rating = item.get("rating")
        date = str(item.get("date") or item.get("published_at") or "")

        return cls(
            title=str(title),
            link=str(link),
            snippet=str(snippet),
            source=str(source),
            engine=engine,
            query=query,
            module=module,
            position=position or int(item.get("position") or 0),
            raw=dict(item),
            phone=phone,
            address=address,
            latitude=float(lat) if lat is not None else None,
            longitude=float(lng) if lng is not None else None,
            rating=float(rating) if rating is not None else None,
            date=date,
        )


@dataclass
class ExtractedEntity:
    """An entity pulled from snippets via NER / regex."""

    entity_type: str  # email | phone | btc | eth | xmr | ip | url | social
    value: str
    context: str = ""
    source_link: str = ""
    confidence: float = 0.8

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttemptedQuery:
    """Tracks every query fired — required for the Zero Records section."""

    module: str
    engine: str
    query: str
    status: str = "ok"  # ok | empty | error
    result_count: int = 0
    filtered_count: int = 0
    error_message: str = ""
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ThreatAssessment:
    """Dynamic risk score for a target."""

    score: int = 0  # 0-100
    level: RiskLevel = RiskLevel.LOW
    factors: List[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level.value if isinstance(self.level, RiskLevel) else self.level,
            "factors": list(self.factors),
            "summary": self.summary,
        }


@dataclass
class InvestigationReport:
    """Top-level container for a full investigation run."""

    target: str
    target_type: str = "auto"  # email | phone | name | username | image | address
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    finished_at: str = ""
    results: List[OSINTResult] = field(default_factory=list)
    entities: List[ExtractedEntity] = field(default_factory=list)
    attempted_queries: List[AttemptedQuery] = field(default_factory=list)
    threat: ThreatAssessment = field(default_factory=ThreatAssessment)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def finalize(self) -> None:
        self.finished_at = datetime.now(timezone.utc).isoformat()

    def deduplicated_results(self) -> List[OSINTResult]:
        """Strict dedup by normalized link, then by title+snippet hash."""
        seen_links = set()
        seen_content = set()
        unique: List[OSINTResult] = []
        for r in self.results:
            link_key = _normalize(r.link).rstrip("/")
            content_key = (_normalize(r.title), _normalize(r.snippet)[:200])
            if link_key and link_key in seen_links:
                continue
            if content_key in seen_content and not link_key:
                continue
            if link_key:
                seen_links.add(link_key)
            seen_content.add(content_key)
            unique.append(r)
        return unique

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "result_count": len(self.deduplicated_results()),
            "results": [r.to_dict() for r in self.deduplicated_results()],
            "entities": [e.to_dict() for e in self.entities],
            "attempted_queries": [q.to_dict() for q in self.attempted_queries],
            "threat": self.threat.to_dict(),
            "metadata": self.metadata,
        }
