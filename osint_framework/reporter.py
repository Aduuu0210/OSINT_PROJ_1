"""
Enterprise reporting engine.

Exports:
  - Nested JSON
  - Flat CSV
  - Human-readable executive summary (TXT) with mandatory Zero-Records section
  - STIX 2.1 bundle for TIP ingestion

All artifacts land in ``reports/osint_report_<timestamp>.*`` with strict dedup.
"""

from __future__ import annotations

import csv
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .models import InvestigationReport, RiskLevel

logger = logging.getLogger("osint.reporter")


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _reports_dir(base: Optional[Union[str, Path]] = None) -> Path:
    if base:
        p = Path(base)
    else:
        p = Path(__file__).resolve().parent / "reports"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _stix_id(obj_type: str) -> str:
    return f"{obj_type}--{uuid.uuid4()}"


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def export_json(
    report: InvestigationReport,
    *,
    output_path: Optional[Union[str, Path]] = None,
    stamp: Optional[str] = None,
) -> str:
    stamp = stamp or _ts()
    out = Path(output_path) if output_path else _reports_dir() / f"osint_report_{stamp}.json"
    out.parent.mkdir(parents=True, exist_ok=True)

    payload = report.to_dict()
    # Strip bulky raw blobs from default JSON for readability; keep a flag
    for r in payload.get("results", []):
        raw = r.pop("raw", None)
        if raw:
            r["raw_keys"] = list(raw.keys())

    with open(out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False, default=str)
    logger.info("Wrote JSON report → %s", out)
    return str(out)


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

def export_csv(
    report: InvestigationReport,
    *,
    output_path: Optional[Union[str, Path]] = None,
    stamp: Optional[str] = None,
) -> str:
    stamp = stamp or _ts()
    out = Path(output_path) if output_path else _reports_dir() / f"osint_report_{stamp}.csv"
    out.parent.mkdir(parents=True, exist_ok=True)

    rows = report.deduplicated_results()
    fieldnames = [
        "title",
        "link",
        "snippet",
        "source",
        "engine",
        "module",
        "query",
        "position",
        "phone",
        "address",
        "latitude",
        "longitude",
        "rating",
        "date",
        "timestamp",
    ]
    with open(out, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow(r.to_dict())
    logger.info("Wrote CSV report → %s", out)
    return str(out)


# ---------------------------------------------------------------------------
# Executive summary (TXT)
# ---------------------------------------------------------------------------

_BANNER = r"""
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║   ██████╗ ███████╗██╗███╗   ██╗████████╗    ███████╗██████╗              ║
║  ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝    ██╔════╝██╔══██╗             ║
║  ██║   ██║███████╗██║██╔██╗ ██║   ██║       █████╗  ██████╔╝             ║
║  ██║   ██║╚════██║██║██║╚██╗██║   ██║       ██╔══╝  ██╔══██╗             ║
║  ╚██████╔╝███████║██║██║ ╚████║   ██║       ██║     ██║  ██║             ║
║   ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝       ╚═╝     ╚═╝  ╚═╝             ║
║                                                                          ║
║            SerpApi-Powered Open Source Intelligence Framework            ║
║                     ENTERPRISE EXECUTIVE SUMMARY                         ║
╚══════════════════════════════════════════════════════════════════════════╝
""".strip(
    "\n"
)


def export_txt(
    report: InvestigationReport,
    *,
    output_path: Optional[Union[str, Path]] = None,
    stamp: Optional[str] = None,
) -> str:
    stamp = stamp or _ts()
    out = Path(output_path) if output_path else _reports_dir() / f"osint_report_{stamp}.txt"
    out.parent.mkdir(parents=True, exist_ok=True)

    results = report.deduplicated_results()
    threat = report.threat
    level = threat.level.value if isinstance(threat.level, RiskLevel) else str(threat.level)

    lines: List[str] = [
        _BANNER,
        "",
        f" Generated (UTC): {report.finished_at or _utc_now_iso()}",
        f" Target:          {report.target}",
        f" Target Type:     {report.target_type}",
        f" Started:         {report.started_at}",
        f" Finished:        {report.finished_at or 'n/a'}",
        f" Validated Hits:  {len(results)}",
        f" Entities Found:  {len(report.entities)}",
        f" Queries Fired:   {len(report.attempted_queries)}",
        "",
        "─" * 78,
        " THREAT ASSESSMENT",
        "─" * 78,
        f" Score : {threat.score} / 100",
        f" Level : {level}",
        f" Summary: {threat.summary}",
        "",
        " Contributing Factors:",
    ]
    if threat.factors:
        for f in threat.factors:
            lines.append(f"   • {f}")
    else:
        lines.append("   • (none)")

    # Categorized findings
    lines += ["", "─" * 78, " CATEGORIZED FINDINGS", "─" * 78]

    by_module: Dict[str, List[Any]] = {}
    for r in results:
        key = r.module or r.engine or "unknown"
        by_module.setdefault(key, []).append(r)

    if not by_module:
        lines.append(" (no validated findings)")
    else:
        for mod, items in sorted(by_module.items(), key=lambda kv: -len(kv[1])):
            lines.append(f"\n [{mod}] — {len(items)} hit(s)")
            for r in items[:25]:
                lines.append(f"   - {r.title or '(no title)'}")
                if r.link:
                    lines.append(f"     URL     : {r.link}")
                if r.snippet:
                    snip = r.snippet.replace("\n", " ")
                    if len(snip) > 180:
                        snip = snip[:179] + "…"
                    lines.append(f"     Snippet : {snip}")
                if r.address or r.phone:
                    lines.append(
                        f"     Place   : {r.address or ''} {r.phone or ''}".rstrip()
                    )
                if r.latitude is not None and r.longitude is not None:
                    lines.append(f"     Coords  : {r.latitude}, {r.longitude}")
            if len(items) > 25:
                lines.append(f"   … {len(items) - 25} more omitted")

    # Entities
    lines += ["", "─" * 78, " EXTRACTED ENTITIES (NER)", "─" * 78]
    if not report.entities:
        lines.append(" (none extracted)")
    else:
        by_type: Dict[str, List[str]] = {}
        for e in report.entities:
            by_type.setdefault(e.entity_type, []).append(e.value)
        for etype, vals in sorted(by_type.items()):
            uniq = sorted(set(vals))
            lines.append(f" {etype.upper()} ({len(uniq)}):")
            for v in uniq[:50]:
                lines.append(f"   • {v}")

    # ------------------------------------------------------------------
    # MANDATORY: Zero Records Discovered section
    # ------------------------------------------------------------------
    lines += [
        "",
        "─" * 78,
        " ZERO RECORDS DISCOVERED",
        "─" * 78,
        " The following queries were attempted but yielded zero validated hits",
        " after anti-false-positive filtering (or returned empty from the engine).",
        "",
    ]
    zero_q = [
        q
        for q in report.attempted_queries
        if q.filtered_count == 0 or q.status in {"empty", "error"}
    ]
    if not zero_q:
        lines.append(" (all attempted queries produced at least one validated hit)")
    else:
        for q in zero_q:
            status = q.status.upper()
            extra = f" err={q.error_message}" if q.error_message else ""
            lines.append(
                f"   [{status}] engine={q.engine} module={q.module} "
                f"raw={q.result_count} kept={q.filtered_count}{extra}"
            )
            lines.append(f"           q: {q.query}")

    # Full query audit trail
    lines += [
        "",
        "─" * 78,
        " FULL QUERY AUDIT TRAIL",
        "─" * 78,
    ]
    for q in report.attempted_queries:
        lines.append(
            f"   [{q.status}] {q.engine}/{q.module} raw={q.result_count} "
            f"kept={q.filtered_count} :: {q.query}"
        )

    lines += [
        "",
        "─" * 78,
        " DISCLAIMER",
        "─" * 78,
        " This report is generated exclusively from open-source intelligence via",
        " SerpApi vertical engines. Findings are only as complete as public indexes.",
        " Always corroborate before taking operational, legal, or HR action.",
        "",
        " END OF REPORT",
        "",
    ]

    text = "\n".join(lines)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(text)
    logger.info("Wrote TXT executive summary → %s", out)
    return str(out)


# ---------------------------------------------------------------------------
# STIX 2.1
# ---------------------------------------------------------------------------

def _identity_sdo() -> Dict[str, Any]:
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": _stix_id("identity"),
        "created": _utc_now_iso(),
        "modified": _utc_now_iso(),
        "name": "OSINT Framework (SerpApi)",
        "identity_class": "organization",
        "sectors": ["technology"],
        "description": "Automated OSINT collection & threat-scoring engine powered by SerpApi.",
    }


def _indicator_pattern_for_target(target: str, target_type: str) -> str:
    """Build a STIX patterning expression for the primary target."""
    t = target.replace("\\", "\\\\").replace("'", "\\'")
    tt = (target_type or "auto").lower()
    if tt == "email" or "@" in target:
        return f"[email-addr:value = '{t}']"
    if tt == "phone":
        digits = re.sub(r"\D", "", target)
        return f"[phone-number:value = '{digits or t}']"
    if tt == "url" or target.startswith("http"):
        return f"[url:value = '{t}']"
    if tt == "image":
        return f"[file:name = '{t}']"
    # Generic observable via artifact note — use user-account / domain-name fallback
    return f"[artifact:payload_bin MATCHES '{re.escape(target)[:80]}']"


def export_stix(
    report: InvestigationReport,
    *,
    output_path: Optional[Union[str, Path]] = None,
    stamp: Optional[str] = None,
) -> str:
    """
    Emit a STIX 2.1 Bundle containing:
      - identity (producing tool)
      - indicator (primary target)
      - observed-data / notes for each validated hit
      - attack-pattern / vulnerability-adjacent groupings via labels
      - grouping linking everything into one investigation
      - report SDO summarizing the threat assessment
    """
    stamp = stamp or _ts()
    out = Path(output_path) if output_path else _reports_dir() / f"osint_report_{stamp}_stix.json"
    out.parent.mkdir(parents=True, exist_ok=True)

    now = _utc_now_iso()
    identity = _identity_sdo()
    identity_id = identity["id"]

    objects: List[Dict[str, Any]] = [identity]

    # Primary indicator
    indicator_id = _stix_id("indicator")
    threat_level = (
        report.threat.level.value
        if isinstance(report.threat.level, RiskLevel)
        else str(report.threat.level)
    )
    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": now,
        "modified": now,
        "created_by_ref": identity_id,
        "name": f"OSINT target: {report.target}",
        "description": report.threat.summary or f"Investigation of {report.target}",
        "indicator_types": ["anomalous-activity"]
        if report.threat.score >= 50
        else ["unknown"],
        "pattern": _indicator_pattern_for_target(report.target, report.target_type),
        "pattern_type": "stix",
        "valid_from": report.started_at or now,
        "labels": [
            "osint",
            f"risk:{threat_level.lower()}",
            f"score:{report.threat.score}",
            f"target-type:{report.target_type}",
        ],
        "confidence": max(0, min(100, report.threat.score)),
    }
    objects.append(indicator)

    # Observed data + notes per hit (capped)
    observed_ids: List[str] = []
    results = report.deduplicated_results()
    for i, r in enumerate(results[:100]):
        obs_id = _stix_id("observed-data")
        observed_ids.append(obs_id)
        objects.append(
            {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": obs_id,
                "created": now,
                "modified": now,
                "created_by_ref": identity_id,
                "first_observed": r.timestamp or now,
                "last_observed": r.timestamp or now,
                "number_observed": 1,
                "objects": {
                    "0": {
                        "type": "url",
                        "value": r.link or f"urn:osint:hit:{i}",
                    }
                },
                # STIX 2.1 prefers object_refs, but embedded objects still widely accepted
                "labels": [
                    "osint-hit",
                    r.engine,
                    (r.module or "module")[:40],
                ],
                "x_osint_title": r.title,
                "x_osint_snippet": (r.snippet or "")[:500],
                "x_osint_source": r.source,
                "x_osint_query": r.query,
                "x_osint_lat": r.latitude,
                "x_osint_lon": r.longitude,
            }
        )

        note_id = _stix_id("note")
        objects.append(
            {
                "type": "note",
                "spec_version": "2.1",
                "id": note_id,
                "created": now,
                "modified": now,
                "created_by_ref": identity_id,
                "abstract": (r.title or "OSINT hit")[:100],
                "content": (
                    f"Module: {r.module}\nEngine: {r.engine}\n"
                    f"Query: {r.query}\nSnippet: {r.snippet}"
                )[:5000],
                "object_refs": [obs_id, indicator_id],
            }
        )

    # Entity indicators (emails, phones, wallets, ips)
    for ent in report.entities[:50]:
        ent_ind_id = _stix_id("indicator")
        if ent.entity_type == "email":
            pattern = f"[email-addr:value = '{ent.value}']"
            ind_types = ["anomalous-activity"]
        elif ent.entity_type == "phone":
            pattern = f"[phone-number:value = '{ent.value}']"
            ind_types = ["anomalous-activity"]
        elif ent.entity_type == "ip":
            pattern = f"[ipv4-addr:value = '{ent.value}']"
            ind_types = ["anomalous-activity"]
        elif ent.entity_type in {"btc", "eth", "xmr"}:
            # No standard cyber SCO — encode as artifact + custom label
            pattern = f"[artifact:payload_bin MATCHES '{ent.value}']"
            ind_types = ["anomalous-activity"]
        elif ent.entity_type == "social":
            pattern = f"[user-account:account_login = '{ent.value.lstrip('@')}']"
            ind_types = ["anomalous-activity"]
        else:
            pattern = f"[artifact:payload_bin MATCHES '{ent.value}']"
            ind_types = ["unknown"]

        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": ent_ind_id,
                "created": now,
                "modified": now,
                "created_by_ref": identity_id,
                "name": f"{ent.entity_type}: {ent.value}",
                "description": ent.context or f"Extracted {ent.entity_type}",
                "indicator_types": ind_types,
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now,
                "labels": ["osint-entity", ent.entity_type],
                "confidence": int(ent.confidence * 100),
            }
        )
        # Relationship: related-to primary indicator
        objects.append(
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": _stix_id("relationship"),
                "created": now,
                "modified": now,
                "created_by_ref": identity_id,
                "relationship_type": "related-to",
                "source_ref": ent_ind_id,
                "target_ref": indicator_id,
            }
        )

    # Grouping for the investigation
    grouping_id = _stix_id("grouping")
    objects.append(
        {
            "type": "grouping",
            "spec_version": "2.1",
            "id": grouping_id,
            "created": now,
            "modified": now,
            "created_by_ref": identity_id,
            "name": f"OSINT Investigation — {report.target}",
            "description": report.threat.summary,
            "context": "suspicious-activity",
            "object_refs": [indicator_id] + observed_ids[:50],
            "labels": ["osint-investigation", f"risk:{threat_level.lower()}"],
        }
    )

    # Report SDO
    report_id = _stix_id("report")
    objects.append(
        {
            "type": "report",
            "spec_version": "2.1",
            "id": report_id,
            "created": now,
            "modified": now,
            "created_by_ref": identity_id,
            "name": f"OSINT Report: {report.target}",
            "description": (
                f"Threat score {report.threat.score}/100 ({threat_level}). "
                f"{report.threat.summary}"
            ),
            "published": now,
            "report_types": ["threat-report", "observed-data"],
            "object_refs": [grouping_id, indicator_id] + observed_ids[:30],
            "labels": [
                "osint",
                "serpapi",
                f"risk:{threat_level.lower()}",
                f"score:{report.threat.score}",
            ],
            "x_osint_factors": list(report.threat.factors),
            "x_osint_target": report.target,
            "x_osint_queries_attempted": len(report.attempted_queries),
            "x_osint_validated_hits": len(results),
        }
    )

    bundle = {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "objects": objects,
    }

    # Prefer stix2 library validation when available, but never hard-fail.
    try:
        from stix2 import parse as stix_parse  # type: ignore

        # Round-trip validates basic shape; allow custom props
        stix_parse(bundle, allow_custom=True)
    except Exception as exc:
        logger.debug("STIX soft-validation skipped/failed: %s", exc)

    with open(out, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=2, ensure_ascii=False, default=str)
    logger.info("Wrote STIX 2.1 bundle → %s", out)
    return str(out)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def export_all(
    report: InvestigationReport,
    *,
    output_dir: Optional[Union[str, Path]] = None,
    stamp: Optional[str] = None,
    include_visuals: bool = True,
) -> Dict[str, Optional[str]]:
    """
    Write JSON + CSV + TXT + STIX (+ optional visuals) with a shared timestamp.
    Returns a dict of artifact paths.
    """
    stamp = stamp or _ts()
    out_dir = _reports_dir(output_dir)
    prefix = out_dir / f"osint_report_{stamp}"

    paths: Dict[str, Optional[str]] = {
        "json": export_json(report, output_path=str(prefix) + ".json", stamp=stamp),
        "csv": export_csv(report, output_path=str(prefix) + ".csv", stamp=stamp),
        "txt": export_txt(report, output_path=str(prefix) + ".txt", stamp=stamp),
        "stix": export_stix(report, output_path=str(prefix) + "_stix.json", stamp=stamp),
        "graph": None,
        "map": None,
    }

    if include_visuals:
        try:
            from .visualizer import generate_all_visuals

            visuals = generate_all_visuals(report, output_dir=out_dir, stamp=stamp)
            paths["graph"] = visuals.get("graph")
            paths["map"] = visuals.get("map")
        except Exception as exc:
            logger.warning("Visualization generation failed: %s", exc)

    return paths
