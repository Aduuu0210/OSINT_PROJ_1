#!/usr/bin/env python3
"""
Offline smoke test for the OSINT Framework.

Runs the real code paths with the SerpApi network transport stubbed out, so it
needs no API key and makes no outbound requests. Intended as a pre-merge /
post-install check:

    python scripts/smoke_test.py

Exits 0 when every check passes, 1 otherwise. Each check prints PASS/FAIL.
"""

from __future__ import annotations

import os
import sys
import tempfile
import traceback
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

TARGET = "john.doe@example.com"
BAD_KEY_MSG = "Invalid API key. Please check your credentials."

_results: list[tuple[str, bool, str]] = []


def check(name: str):
    """Decorator: run fn, record PASS/FAIL, never abort the suite."""
    def wrap(fn):
        def runner():
            try:
                fn()
                _results.append((name, True, ""))
                print(f"  PASS  {name}")
            except Exception as exc:
                _results.append((name, False, f"{type(exc).__name__}: {exc}"))
                print(f"  FAIL  {name}\n        {type(exc).__name__}: {exc}")
                traceback.print_exc(limit=3)
        return runner
    return wrap


# ---------------------------------------------------------------------------
# Stub transports
# ---------------------------------------------------------------------------

def _hit(i: int) -> dict:
    return {
        "title": f"Profile of John Doe #{i}",
        "link": f"https://example.com/u/{i}",
        "snippet": f"Reach {TARGET} or +1 415-555-0100. Resume PDF indexed.",
        "displayed_link": "example.com",
        "position": 1,
    }


class OkClient:
    """Every query succeeds and returns one exact-match hit."""

    def __init__(self, *a, **k):
        self._call_count = 0
        self.max_workers = k.get("max_workers", 4)

    @property
    def call_count(self):
        return self._call_count

    def search(self, params, **k):
        self._call_count += 1
        return {"organic_results": [_hit(self._call_count)],
                "search_metadata": {"status": "Success"}}

    def search_results(self, params, **k):
        return self.search(params)

    def extract_items(self, resp, *a, **k):
        return (resp or {}).get("organic_results") or []

    def batch_search(self, param_list, *, progress_callback=None):
        out = []
        for i, p in enumerate(param_list):
            out.append((p, self.search(p), None))
            if progress_callback:
                progress_callback(i + 1, len(param_list), p)
        return out


class FailingClient:
    """Every query errors — invalid key / exhausted quota / network down."""

    def __init__(self, *a, **k):
        self._call_count = 0
        self.max_workers = k.get("max_workers", 4)

    @property
    def call_count(self):
        return self._call_count

    def search(self, params, **k):
        self._call_count += 1
        raise RuntimeError(BAD_KEY_MSG)

    def search_results(self, params, **k):
        return self.search(params)

    def extract_items(self, *a, **k):
        return []

    def batch_search(self, param_list, *, progress_callback=None):
        return [(p, {}, BAD_KEY_MSG) for p in param_list]


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

@check("package imports resolve")
def t_imports():
    from osint_framework.main import run_investigation, build_parser  # noqa: F401
    from osint_framework.analytics import analyze_report, detect_target_type  # noqa: F401
    from osint_framework.models import InvestigationReport  # noqa: F401
    from osint_framework.modules import (  # noqa: F401
        LensSearchModule, MapsSearchModule, NewsSearchModule, WebDorksModule,
    )
    from osint_framework.reporter import export_all  # noqa: F401


@check("target classification handles hostile input")
def t_detect():
    from osint_framework.analytics import detect_target_type
    for raw in ["", "   ", "a" * 5000, "😀 emoji", "' OR 1=1 --", "<script>x</script>",
                "../../../etc/passwd", "%00null", "\n\r\t", "@", "日本語"]:
        detect_target_type(raw)  # must not raise
    assert detect_target_type(TARGET) == "email"
    assert detect_target_type("+1 415-555-0100") == "phone"
    assert detect_target_type("https://x.com/a.jpg") == "image"


@check("anti-false-positive filter rejects non-matching hits")
def t_antifp():
    from osint_framework.models import is_valid_hit
    assert is_valid_hit(TARGET, {"title": f"About {TARGET}", "snippet": "x"}) is True
    assert is_valid_hit(TARGET, {"title": "Unrelated person", "snippet": "nothing"}) is False
    assert is_valid_hit("", {"title": "anything"}) is False


@check("successful run: hits, exports, no false alarm")
def t_success():
    import osint_framework.main as m
    tmp = tempfile.mkdtemp()
    with mock.patch.object(m, "SerpApiClient", OkClient):
        rep = m.run_investigation(TARGET, api_key="k", modules=["web"],
                                 export=True, output_dir=tmp, include_visuals=True)
    hits = rep.deduplicated_results()
    assert len(hits) > 0, "expected validated hits"
    assert rep.metadata.get("collection_incomplete") is False, "clean run flagged incomplete"
    assert rep.metadata.get("errored_queries") == 0
    assert "No conclusion can be drawn" not in rep.threat.summary
    exports = rep.metadata.get("exports") or {}
    for kind in ("json", "csv", "txt", "stix"):
        assert exports.get(kind) and os.path.exists(exports[kind]), f"missing {kind} export"
    assert exports.get("graph") and os.path.exists(exports["graph"]), "missing graph export"


@check("total API failure never reports a clean result")
def t_integrity_guard():
    import osint_framework.main as m
    tmp = tempfile.mkdtemp()
    with mock.patch.object(m, "SerpApiClient", FailingClient):
        rep = m.run_investigation(TARGET, api_key="BAD", modules=["web", "news"],
                                 export=True, output_dir=tmp, include_visuals=False)
    assert rep.metadata.get("collection_incomplete") is True
    assert rep.metadata.get("errored_queries", 0) > 0
    assert rep.metadata.get("errors"), "error messages not surfaced"
    assert "No conclusion can be drawn" in rep.threat.summary, \
        "failed run still reads as a clean assessment"
    assert "INCOMPLETE" in rep.threat.summary
    assert any("incomplete" in f.lower() for f in rep.threat.factors)
    # The exported artefacts must carry the same warning the UI shows.
    txt = (rep.metadata.get("exports") or {}).get("txt")
    assert txt and "INCOMPLETE" in open(txt, encoding="utf-8").read()


@check("CLI exit codes: 0 clean, 2 usage, 3 incomplete")
def t_cli_exit_codes():
    import osint_framework.main as m
    assert m.main([]) == 2, "no-arg invocation should exit 2"
    tmp = tempfile.mkdtemp()
    with mock.patch.object(m, "SerpApiClient", FailingClient):
        code = m.main(["-t", TARGET, "--api-key", "BAD", "--modules", "web",
                       "--output-dir", tmp, "--no-visuals"])
    assert code == 3, f"incomplete run should exit 3, got {code}"


@check("failed/succeeded query counters can never contradict")
def t_counter_consistency():
    import osint_framework.main as m
    tmp = tempfile.mkdtemp()
    with mock.patch.object(m, "SerpApiClient", FailingClient):
        rep = m.run_investigation(TARGET, api_key="BAD", modules=["web"],
                                 export=False, include_visuals=False)
    failed = rep.metadata.get("errored_queries", 0)
    total = rep.metadata.get("total_queries", 0)
    assert total >= failed > 0, f"counters inconsistent: {failed}/{total}"


@check("error messages tell the user what to do next")
def t_actionable_errors():
    import osint_framework.main as m

    # Missing key: must name where to get one and point at the README.
    err = m.build_parser()
    assert err is not None
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        code = m.main(["-t", TARGET])
    out = buf.getvalue()
    assert code == 2
    assert "serpapi.com" in out, f"missing-key error does not say where to get a key: {out}"
    assert "README.md" in out, "missing-key error does not point at the docs"

    # Missing target: must show a runnable example.
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        code = m.main(["--api-key", "k"])
    out = buf.getvalue()
    assert code == 2
    assert "--target" in out or "-t " in out, "usage error does not show the flag"


@check("UI guidance names the key source when no key is set")
def t_ui_key_guidance():
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file(str(REPO_ROOT / "osint_framework" / "app.py"), default_timeout=120)
    at.run()
    at.sidebar.text_input[0].set_value("")            # no key
    at.sidebar.text_input[1].set_value(TARGET)        # but a target
    at.run()
    at.sidebar.button[0].click()
    at.run()
    assert not at.exception, at.exception[0].value if at.exception else "exception"
    assert at.error, "expected a validation error for the missing key"
    shown = " ".join(e.value for e in at.error)
    assert "serpapi.com" in shown, "UI does not tell the user where to get a key"
    assert "SERPAPI_API_KEY" in shown, "UI does not mention the env var"


@check("Streamlit UI renders with no exceptions")
def t_ui_renders():
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file(str(REPO_ROOT / "osint_framework" / "app.py"), default_timeout=120)
    at.run()
    assert not at.exception, at.exception[0].value if at.exception else "exception"
    assert [b.label for b in at.button] == ["🚀 Run Investigation"]


@check("UI surfaces the incomplete-collection warning")
def t_ui_incomplete_banner():
    from streamlit.testing.v1 import AppTest
    from osint_framework.models import InvestigationReport, RiskLevel, ThreatAssessment

    rep = InvestigationReport(target=TARGET, target_type="email")
    rep.threat = ThreatAssessment(score=0, level=RiskLevel.LOW,
                                 summary="No conclusion can be drawn.")
    # Deliberately inconsistent: counters set, query list empty.
    rep.metadata.update(collection_incomplete=True, errored_queries=18,
                        total_queries=18, errors=[BAD_KEY_MSG])
    at = AppTest.from_file(str(REPO_ROOT / "osint_framework" / "app.py"), default_timeout=120)
    at.session_state["report"] = rep
    at.session_state["exports"] = {}
    at.run()
    assert not at.exception, at.exception[0].value if at.exception else "exception"
    shown = " ".join(e.value for e in at.error)
    assert "Coverage warning" in shown, "no coverage warning rendered"
    assert "18 of 18" in shown, f"counters rendered inconsistently: {shown[:160]}"
    assert "of 0 queries" not in shown, "rendered an impossible 18-of-0 count"


@check("UI full journey: form -> run -> results")
def t_ui_journey():
    from streamlit.testing.v1 import AppTest
    import osint_framework.main as m

    tmp = tempfile.mkdtemp()
    with mock.patch.object(m, "SerpApiClient", OkClient):
        at = AppTest.from_file(str(REPO_ROOT / "osint_framework" / "app.py"),
                              default_timeout=180)
        at.run()
        at.sidebar.text_input[0].set_value("sk_test_dummy")
        at.sidebar.text_input[1].set_value(TARGET)
        at.run()
        at.sidebar.button[0].click()
        at.run()
    assert not at.exception, at.exception[0].value if at.exception else "exception"
    assert at.success, "expected a success banner after a clean run"
    assert len(at.tabs) == 7, f"expected 7 tabs, got {len(at.tabs)}"


def main() -> int:
    print(f"OSINT Framework smoke test — python {sys.version.split()[0]}")
    print(f"repo root: {REPO_ROOT}\n")
    for fn in (t_imports, t_detect, t_antifp, t_success, t_integrity_guard,
               t_cli_exit_codes, t_counter_consistency, t_actionable_errors,
               t_ui_key_guidance, t_ui_renders, t_ui_incomplete_banner,
               t_ui_journey):
        fn()
    passed = sum(1 for _, ok, _ in _results if ok)
    failed = len(_results) - passed
    print(f"\n{passed} passed, {failed} failed, {len(_results)} total")
    if failed:
        print("\nFailed checks:")
        for name, ok, msg in _results:
            if not ok:
                print(f"  - {name}: {msg}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
