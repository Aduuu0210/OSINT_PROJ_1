#!/usr/bin/env python3
"""
CLI entry point for the SerpApi-powered OSINT Framework.

Examples
--------
  python -m osint_framework.main -t "john.doe@example.com" --api-key $SERPAPI_API_KEY
  python -m osint_framework.main -t "+1 415-555-0100" --modules web,maps,news
  python -m osint_framework.main -t "Alice Smith" --image-url https://example.com/face.jpg
  python -m osint_framework.main --ui
  streamlit run osint_framework/app.py
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Callable, List, Optional

# ---------------------------------------------------------------------------
# Path / package bootstrap
# Works for:
#   python -m osint_framework.main
#   python osint_framework/main.py
#   import via streamlit (app.py imports run_investigation)
# ---------------------------------------------------------------------------
_THIS_FILE = Path(__file__).resolve()
_PKG_DIR = _THIS_FILE.parent
_REPO_ROOT = _PKG_DIR.parent

if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

if __name__ == "__main__" and (__package__ is None or __package__ == ""):
    __package__ = "osint_framework"

try:
    from .analytics import analyze_report, detect_target_type
    from .models import InvestigationReport
    from .modules import LensSearchModule, MapsSearchModule, NewsSearchModule, WebDorksModule
    from .reporter import export_all
    from .serpapi_client import SerpApiClient, SerpApiError
except (ImportError, SystemError):
    try:
        from osint_framework.analytics import analyze_report, detect_target_type
        from osint_framework.models import InvestigationReport
        from osint_framework.modules import (
            LensSearchModule, MapsSearchModule, NewsSearchModule, WebDorksModule,
        )
        from osint_framework.reporter import export_all
        from osint_framework.serpapi_client import SerpApiClient, SerpApiError
    except ImportError:
        if str(_PKG_DIR) not in sys.path:
            sys.path.insert(0, str(_PKG_DIR))
        from analytics import analyze_report, detect_target_type  # type: ignore
        from models import InvestigationReport  # type: ignore
        from modules import (  # type: ignore
            LensSearchModule, MapsSearchModule, NewsSearchModule, WebDorksModule,
        )
        from reporter import export_all  # type: ignore
        from serpapi_client import SerpApiClient, SerpApiError  # type: ignore

LOG_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format=LOG_FORMAT, datefmt="%H:%M:%S")
    # Quieter underlying HTTP libs
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


logger = logging.getLogger("osint.main")


# ---------------------------------------------------------------------------
# Investigation orchestrator (shared by CLI + Streamlit)
# ---------------------------------------------------------------------------

MODULE_MAP = {
    "web": "web",
    "web_dorks": "web",
    "dorks": "web",
    "lens": "lens",
    "lens_search": "lens",
    "maps": "maps",
    "maps_search": "maps",
    "news": "news",
    "news_search": "news",
}


def run_investigation(
    target: str,
    *,
    api_key: Optional[str] = None,
    modules: Optional[List[str]] = None,
    target_type: str = "auto",
    image_url: Optional[str] = None,
    max_workers: int = 4,
    num_per_query: int = 10,
    progress_callback: Optional[Callable[[str], None]] = None,
    export: bool = True,
    output_dir: Optional[str] = None,
    include_visuals: bool = True,
) -> InvestigationReport:
    """
    Full pipeline: multi-engine search → anti-FP filter → NER → threat score → export.
    """
    def progress(msg: str) -> None:
        logger.info(msg)
        if progress_callback:
            try:
                progress_callback(msg)
            except Exception:
                pass

    target = (target or "").strip()
    if not target and not image_url:
        raise ValueError("A target string or --image-url is required.")

    # If only image given, use URL as target label
    if not target and image_url:
        target = image_url

    if target_type == "auto":
        target_type = detect_target_type(image_url or target)

    client = SerpApiClient(api_key=api_key, max_workers=max_workers)

    report = InvestigationReport(target=target, target_type=target_type)
    report.metadata["image_url"] = image_url
    report.metadata["max_workers"] = max_workers

    # Resolve module list
    if not modules:
        modules = ["web", "news", "maps"]
        if image_url or target_type == "image":
            modules.append("lens")
    normalized: List[str] = []
    for m in modules:
        key = MODULE_MAP.get(m.strip().lower())
        if key and key not in normalized:
            normalized.append(key)
    if not normalized:
        normalized = ["web"]

    progress(
        f"Starting investigation target='{target}' type={target_type} modules={normalized}"
    )

    # ---- Web dorks ----
    if "web" in normalized:
        mod = WebDorksModule(client)
        try:
            out = mod.run(
                target,
                target_type=target_type,
                num_per_query=num_per_query,
                progress=progress,
            )
            report.results.extend(out["results"])
            report.attempted_queries.extend(out["attempted"])
        except SerpApiError as exc:
            progress(f"[web_dorks] FATAL: {exc}")
            report.metadata.setdefault("errors", []).append(str(exc))

    # ---- News ----
    if "news" in normalized:
        mod = NewsSearchModule(client)
        try:
            out = mod.run(target, target_type=target_type, progress=progress)
            report.results.extend(out["results"])
            report.attempted_queries.extend(out["attempted"])
        except SerpApiError as exc:
            progress(f"[news_search] FATAL: {exc}")
            report.metadata.setdefault("errors", []).append(str(exc))

    # ---- Maps ----
    if "maps" in normalized:
        mod = MapsSearchModule(client)
        try:
            out = mod.run(target, target_type=target_type, progress=progress)
            report.results.extend(out["results"])
            report.attempted_queries.extend(out["attempted"])
        except SerpApiError as exc:
            progress(f"[maps_search] FATAL: {exc}")
            report.metadata.setdefault("errors", []).append(str(exc))

    # ---- Lens ----
    if "lens" in normalized:
        mod = LensSearchModule(client)
        try:
            out = mod.run(target, image_url=image_url, progress=progress)
            report.results.extend(out["results"])
            report.attempted_queries.extend(out["attempted"])
        except SerpApiError as exc:
            progress(f"[lens_search] FATAL: {exc}")
            report.metadata.setdefault("errors", []).append(str(exc))

    progress(
        f"Search phase complete — raw retained rows={len(report.results)} "
        f"(pre-dedup), queries={len(report.attempted_queries)}, "
        f"api_calls={client.call_count}"
    )

    # Analytics
    progress("Running entity extraction + threat scoring…")
    analyze_report(report)
    report.finalize()
    report.metadata["api_calls"] = client.call_count
    report.metadata["deduped_hits"] = len(report.deduplicated_results())

    # ------------------------------------------------------------------
    # Collection-integrity guard.
    #
    # A score of 0 means "nothing incriminating was found" ONLY IF the
    # searches actually ran. When queries errored (invalid/expired API key,
    # quota exhausted, network failure) the report must never present itself
    # as a clean assessment — that is a false negative an analyst would act on.
    # ------------------------------------------------------------------
    errored = [q for q in report.attempted_queries if q.status == "error"]
    total_q = len(report.attempted_queries)
    report.metadata["errored_queries"] = len(errored)
    report.metadata["total_queries"] = total_q
    report.metadata["collection_incomplete"] = bool(errored)

    if errored:
        seen: List[str] = []
        for q in errored:
            msg = (q.error_message or "unknown error").strip()
            if msg and msg not in seen:
                seen.append(msg)
        report.metadata["errors"] = seen
        detail = "; ".join(seen[:3]) or "unspecified query errors"
        note = (
            f"INCOMPLETE INVESTIGATION: {len(errored)} of {total_q} queries failed "
            f"({detail}). The score reflects only the searches that succeeded and "
            f"MUST NOT be read as a clean result."
        )
        if report.threat.score == 0:
            # Replace the misleading "all clear" wording entirely.
            report.threat.summary = (
                f"No conclusion can be drawn for '{report.target}'. {note}"
            )
        else:
            report.threat.summary = f"{report.threat.summary} {note}"
        if f"Investigation incomplete: {len(errored)}/{total_q} queries failed." not in (
            report.threat.factors
        ):
            report.threat.factors.insert(
                0, f"Investigation incomplete: {len(errored)}/{total_q} queries failed."
            )
        progress(
            f"WARNING — collection incomplete: {len(errored)}/{total_q} queries failed. "
            f"Report is NOT a clean result. First error: {seen[0] if seen else 'unknown'}"
        )

    progress(

        f"Threat score={report.threat.score}/100 ({report.threat.level.value}) "
        f"entities={len(report.entities)} hits={report.metadata['deduped_hits']}"
    )

    if export:
        progress("Exporting enterprise reports…")
        paths = export_all(
            report,
            output_dir=output_dir,
            include_visuals=include_visuals,
        )
        report.metadata["exports"] = paths
        for kind, path in paths.items():
            if path:
                progress(f"  • {kind}: {path}")

    progress("Investigation complete.")
    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="osint-framework",
        description="SerpApi-powered OSINT Framework — multi-engine, anti-FP, enterprise reporting.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("-t", "--target", help="Investigation target (email, phone, name, username, URL).")
    p.add_argument(
        "--image-url",
        help="Image URL for Google Lens reverse-image search (catfish / avatar reuse).",
    )
    p.add_argument(
        "--api-key",
        default=os.environ.get("SERPAPI_API_KEY") or os.environ.get("SERP_API_KEY"),
        help="SerpApi API key (or set SERPAPI_API_KEY).",
    )
    p.add_argument(
        "--modules",
        default="web,news,maps",
        help="Comma-separated modules: web,news,maps,lens (default: web,news,maps).",
    )
    p.add_argument(
        "--target-type",
        default="auto",
        choices=["auto", "email", "phone", "name", "username", "image", "address", "url"],
        help="Force target classification (default: auto-detect).",
    )
    p.add_argument("--max-workers", type=int, default=4, help="ThreadPool worker count.")
    p.add_argument("--num", type=int, default=10, help="Results per Google query (num=).")
    p.add_argument(
        "--output-dir",
        default=None,
        help="Report output directory (default: osint_framework/reports/).",
    )
    p.add_argument("--no-export", action="store_true", help="Skip writing report files.")
    p.add_argument("--no-visuals", action="store_true", help="Skip graph/map generation.")
    p.add_argument("--ui", action="store_true", help="Launch the Streamlit web dashboard.")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging.")
    return p


def launch_ui() -> int:
    """Spawn Streamlit against app.py with WSL-safe flags."""
    app_path = Path(__file__).resolve().parent / "app.py"
    env_pythonpath = os.environ.get("PYTHONPATH", "")
    parts = [p for p in env_pythonpath.split(os.pathsep) if p]
    if str(_REPO_ROOT) not in parts:
        parts.insert(0, str(_REPO_ROOT))
    os.environ["PYTHONPATH"] = os.pathsep.join(parts)

    cmd_flags = [
        "--server.headless=true",
        "--server.address=0.0.0.0",
        "--server.port=8501",
        "--browser.gatherUsageStats=false",
    ]
    try:
        from streamlit.web import cli as stcli
        sys.argv = ["streamlit", "run", str(app_path), *cmd_flags]
        return stcli.main()
    except Exception:
        import subprocess
        cmd = [sys.executable, "-m", "streamlit", "run", str(app_path), *cmd_flags]
        logger.info("Launching Streamlit: %s", " ".join(cmd))
        return subprocess.call(cmd)


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(verbose=args.verbose)

    if args.ui:
        return launch_ui()

    if not args.target and not args.image_url:
        parser.print_help()
        print("\nError: provide --target and/or --image-url (or pass --ui).", file=sys.stderr)
        return 2

    if not args.api_key:
        print(
            "Error: SerpApi API key required. Pass --api-key or export SERPAPI_API_KEY.",
            file=sys.stderr,
        )
        return 2

    modules = [m.strip() for m in (args.modules or "").split(",") if m.strip()]

    try:
        report = run_investigation(
            target=args.target or "",
            api_key=args.api_key,
            modules=modules,
            target_type=args.target_type,
            image_url=args.image_url,
            max_workers=args.max_workers,
            num_per_query=args.num,
            export=not args.no_export,
            output_dir=args.output_dir,
            include_visuals=not args.no_visuals,
        )
    except Exception as exc:
        logger.exception("Investigation failed: %s", exc)
        return 1

    # Console summary
    hits = report.deduplicated_results()
    print("\n" + "=" * 64)
    print(f" TARGET : {report.target}")
    print(f" TYPE   : {report.target_type}")
    print(f" HITS   : {len(hits)}")
    print(f" ENTITIES: {len(report.entities)}")
    print(f" THREAT : {report.threat.score}/100  [{report.threat.level.value}]")
    print(f" SUMMARY: {report.threat.summary}")
    exports = report.metadata.get("exports") or {}
    if exports:
        print(" EXPORTS:")
        for k, v in exports.items():
            if v:
                print(f"   - {k}: {v}")
    incomplete = bool(report.metadata.get("collection_incomplete"))
    if incomplete:
        print(
            f" WARNING: {report.metadata.get('errored_queries', 0)}/"
            f"{len(report.attempted_queries)} queries failed — report is INCOMPLETE."
        )
        for err in (report.metadata.get("errors") or [])[:3]:
            print(f"   ! {err}")
    print("=" * 64 + "\n")
    # Distinct exit code so scripts / CI never treat a partial run as success.
    return 3 if incomplete else 0


if __name__ == "__main__":
    raise SystemExit(main())
