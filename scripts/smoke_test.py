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


# ---------------------------------------------------------------------------
# HIBP fakes
# ---------------------------------------------------------------------------

HIBP_BREACH = {
    "Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com",
    "BreachDate": "2013-10-04", "PwnCount": 152445165,
    "DataClasses": ["Email addresses", "Passwords"],
    "IsVerified": True, "IsSensitive": False, "IsRetired": False,
    "IsSpamList": False,
}


class _FakeResp:
    def __init__(self, code, payload=None):
        self.status_code = code
        self._p = payload

    def json(self):
        if self._p is None:
            raise ValueError("no payload")
        return self._p


class FakeHibpSession:
    """Scripts HIBP responses by URL substring; records headers sent."""

    def __init__(self, breach_code=200, paste_code=404, payload=None):
        self.breach_code = breach_code
        self.paste_code = paste_code
        self.payload = payload if payload is not None else [HIBP_BREACH]
        self.calls = []

    def get(self, url, headers=None, params=None, timeout=None):
        self.calls.append((url, dict(headers or {})))
        if "breachedaccount" in url:
            return _FakeResp(self.breach_code, self.payload)
        if "pasteaccount" in url:
            return _FakeResp(self.paste_code)
        return _FakeResp(404)


def _hibp_module(session, *, api_key="a" * 32):
    from osint_framework.hibp_client import HibpClient
    from osint_framework.modules import HibpBreachModule
    # min_interval=0 and max_retries=0 keep the suite fast and deterministic.
    return HibpBreachModule(
        client=HibpClient(api_key=api_key, session=session, min_interval=0, max_retries=0)
    )


def _sidebar_input(at, label: str):
    """
    Find a sidebar text input by its label rather than its position.

    Positional indexing silently breaks whenever a field is added or reordered —
    it once made a check pass by typing the target into the API-key box.
    """
    for ti in at.sidebar.text_input:
        if ti.label == label:
            return ti
    labels = [ti.label for ti in at.sidebar.text_input]
    raise AssertionError(f"no sidebar input labelled {label!r}; found {labels}")


def _sidebar_check(at, label: str):
    for cb in at.sidebar.checkbox:
        if cb.label == label:
            return cb
    labels = [cb.label for cb in at.sidebar.checkbox]
    raise AssertionError(f"no sidebar checkbox labelled {label!r}; found {labels}")


@check("HIBP: missing key is an error, never 'no breaches'")
def t_hibp_no_key():
    mod = _hibp_module(FakeHibpSession(), api_key="")
    out = mod.run("victim@example.com")
    assert out["attempted"], "expected attempted-query records"
    assert all(q.status == "error" for q in out["attempted"]), \
        "a skipped-for-no-key lookup must not read as success"
    assert not out["results"]
    assert "not performed" in out["attempted"][0].error_message.lower()


@check("HIBP: 404 is a genuine negative, not a failure")
def t_hibp_404_is_clean():
    mod = _hibp_module(FakeHibpSession(breach_code=404))
    out = mod.run("victim@example.com")
    assert out["attempted"]
    assert all(q.status in ("empty", "ok") for q in out["attempted"]), \
        "HTTP 404 means 'no breaches' and must not be recorded as an error"
    assert not any(q.status == "error" for q in out["attempted"])
    assert not out["results"]


@check("HIBP: confirmed breach is returned, keyed and attributed")
def t_hibp_found():
    sess = FakeHibpSession()
    mod = _hibp_module(sess)
    out = mod.run("victim@example.com")
    assert out["results"], "expected at least one breach result"
    r = out["results"][0]
    assert r.module == "hibp_breach" and r.engine == "hibp"
    assert "victim@example.com" in r.snippet, "result must name the queried account"
    assert "Adobe" in r.title
    # Auth header + required User-Agent must actually be sent.
    assert any("hibp-api-key" in h for _, h in sess.calls), "no hibp-api-key header"
    assert all(h.get("User-Agent") for _, h in sess.calls), "User-Agent is mandatory for HIBP"


@check("HIBP: auth/rate/server errors are recorded as errors")
def t_hibp_error_codes():
    for code in (401, 403, 429, 503, 418):
        mod = _hibp_module(FakeHibpSession(breach_code=code))
        out = mod.run("victim@example.com")
        assert any(q.status == "error" for q in out["attempted"]), \
            f"HTTP {code} was not recorded as an error"


@check("HIBP: non-email targets are skipped, not silently clean")
def t_hibp_skip_non_email():
    mod = _hibp_module(FakeHibpSession())
    for target in ["+1 415-555-0100", "Jane Doe", "@handle"]:
        out = mod.run(target)
        assert out["attempted"], f"no audit row for {target}"
        assert out["attempted"][0].status == "skipped", \
            f"{target} should be recorded as skipped"


@check("HIBP: confirmed breach raises the score without double-counting")
def t_hibp_scoring():
    from osint_framework.analytics import ThreatScorer
    from osint_framework.models import OSINTResult

    t = "victim@example.com"
    hibp_row = OSINTResult(
        title="HIBP: Adobe", link="https://haveibeenpwned.com/breach/Adobe",
        snippet=f"{t} exposed in the Adobe breach — data classes: Email addresses, Passwords",
        engine="hibp", module="hibp_breach", raw={"kind": "breaches", "name": "Adobe"},
    )
    scorer = ThreatScorer()

    alone = scorer.score([hibp_row], [], target=t)
    assert any("CONFIRMED data-breach" in f for f in alone.factors)
    assert alone.score >= 25, f"confirmed breach scored only {alone.score}"
    # The keyword sweep must not re-count the same fact.
    assert not any("credential-leak language" in f for f in alone.factors), \
        "HIBP snippet double-counted by the keyword sweep"

    # Independent Google evidence still scores on its own.
    g = OSINTResult(title="Forum", link="https://f.example/x",
                    snippet=f"{t} appeared in a breach leak dump",
                    engine="google", module="web_dorks")
    both = scorer.score([hibp_row, g], [], target=t)
    assert both.score > alone.score, "independent breach evidence did not add signal"


@check("HIBP runs alongside the Google modules in one investigation")
def t_hibp_with_google():
    import osint_framework.main as m
    from osint_framework.hibp_client import HibpClient
    from osint_framework.modules import HibpBreachModule

    tmp = tempfile.mkdtemp()
    sess = FakeHibpSession()
    real = m.HibpBreachModule

    def fake_ctor(api_key=None, **kw):
        return real(client=HibpClient(api_key=api_key, session=sess, min_interval=0))

    with mock.patch.object(m, "SerpApiClient", OkClient), \
         mock.patch.object(m, "HibpBreachModule", fake_ctor):
        rep = m.run_investigation(TARGET, api_key="k", hibp_api_key="b" * 32,
                                  modules=["web", "news", "hibp"],
                                  export=False, include_visuals=False)

    mods = {q.module for q in rep.attempted_queries}
    assert {"web_dorks", "news_search", "hibp_breach"} <= mods, f"missing modules: {mods}"
    engines = {r.engine for r in rep.deduplicated_results()}
    assert "hibp" in engines and "google" in engines, f"engines: {engines}"
    assert rep.metadata.get("collection_incomplete") is False, \
        "a fully successful run must not be flagged incomplete"


@check("HIBP enabled without a key flags the whole report incomplete")
def t_hibp_no_key_flags_incomplete():
    import osint_framework.main as m
    tmp = tempfile.mkdtemp()
    with mock.patch.object(m, "SerpApiClient", OkClient), \
         mock.patch.dict(os.environ, {}, clear=False):
        os.environ.pop("HIBP_API_KEY", None)
        os.environ.pop("HIBP_KEY", None)
        rep = m.run_investigation(TARGET, api_key="k", hibp_api_key=None,
                                  modules=["web", "hibp"],
                                  export=True, output_dir=tmp, include_visuals=False)
    assert rep.metadata.get("collection_incomplete") is True, \
        "Google succeeded but the requested breach check never ran — must be flagged"
    hibp_qs = [q for q in rep.attempted_queries if q.module == "hibp_breach"]
    assert hibp_qs and all(q.status == "error" for q in hibp_qs)
    txt = (rep.metadata.get("exports") or {}).get("txt")
    assert txt and "INCOMPLETE" in open(txt, encoding="utf-8").read()


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
    _sidebar_input(at, "SerpApi API Key").set_value("")   # no key
    _sidebar_input(at, "Target").set_value(TARGET)        # but a target
    at.run()
    at.sidebar.button[0].click()
    at.run()
    assert not at.exception, at.exception[0].value if at.exception else "exception"
    assert at.error, "expected a validation error for the missing key"
    shown = " ".join(e.value for e in at.error)
    assert "serpapi.com" in shown, "UI does not tell the user where to get a key"
    assert "SERPAPI_API_KEY" in shown, "UI does not mention the env var"
    # Guard against the check passing for the wrong reason: the missing-key
    # error must fire, not the "nothing to investigate" one.
    assert "Nothing to investigate" not in shown, \
        "target was not set correctly; the wrong validation error fired"


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
        _sidebar_input(at, "SerpApi API Key").set_value("sk_test_dummy")
        _sidebar_input(at, "Target").set_value(TARGET)
        # HIBP is opt-in and has no key here; keep it off so the run is clean.
        _sidebar_check(at, "HIBP Breach").set_value(False)
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
               t_cli_exit_codes, t_counter_consistency,
               t_hibp_no_key, t_hibp_404_is_clean, t_hibp_found,
               t_hibp_error_codes, t_hibp_skip_non_email, t_hibp_scoring,
               t_hibp_with_google, t_hibp_no_key_flags_incomplete,
               t_actionable_errors, t_ui_key_guidance, t_ui_renders,
               t_ui_incomplete_banner, t_ui_journey):
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
