#!/usr/bin/env python3
"""
Streamlit dark-mode OSINT dashboard.

Launch (from repo root):
    streamlit run osint_framework/app.py
    python -m osint_framework.main --ui
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import List

# ---------------------------------------------------------------------------
# Path bootstrap — MUST run before any osint_framework imports.
# Handles:
#   • streamlit run osint_framework/app.py   (cwd = repo root)
#   • streamlit run app.py                   (cwd = osint_framework/)
#   • WSL paths under /mnt/c/...
# ---------------------------------------------------------------------------
_THIS_FILE = Path(__file__).resolve()
_PKG_DIR = _THIS_FILE.parent                 # .../osint_framework
_REPO_ROOT = _PKG_DIR.parent                 # repo root

for _path in (str(_REPO_ROOT), str(_PKG_DIR)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

# Ensure PYTHONPATH is also set for any child processes Streamlit may spawn
_existing = os.environ.get("PYTHONPATH", "")
_parts = [p for p in _existing.split(os.pathsep) if p]
for _path in (str(_REPO_ROOT),):
    if _path not in _parts:
        _parts.insert(0, _path)
os.environ["PYTHONPATH"] = os.pathsep.join(_parts)

import streamlit as st  # noqa: E402

# Prefer package imports; fall back to flat imports if package isn't resolvable
try:
    from osint_framework.analytics import detect_target_type
    from osint_framework.main import run_investigation
    from osint_framework.models import InvestigationReport
except ModuleNotFoundError:
    try:
        from analytics import detect_target_type  # type: ignore
        from main import run_investigation  # type: ignore
        from models import InvestigationReport  # type: ignore
    except ModuleNotFoundError as _imp_err:
        st.set_page_config(page_title="OSINT Framework — Import Error", layout="wide")
        st.error(
            "**Import error:** could not load `osint_framework` package.\n\n"
            f"Details: `{_imp_err}`\n\n"
            "Fix:\n"
            "1. `cd` into the **repo root** (the folder that contains `osint_framework/`)\n"
            "2. `pip install -r requirements.txt`\n"
            "3. `export PYTHONPATH=\"$(pwd):$PYTHONPATH\"`\n"
            "4. `streamlit run osint_framework/app.py --server.headless true`"
        )
        st.code(
            f"sys.path = {sys.path[:8]}\n"
            f"REPO_ROOT = {_REPO_ROOT}\n"
            f"PKG_DIR   = {_PKG_DIR}\n"
            f"cwd       = {Path.cwd()}",
            language="text",
        )
        st.stop()

# ---------------------------------------------------------------------------
# Page config + dark theme polish
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="OSINT Framework | SerpApi",
    page_icon="🕵️",
    layout="wide",
    initial_sidebar_state="expanded",
)

CUSTOM_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;600;700&display=swap');

    .stApp {
        background: radial-gradient(ellipse at top, #141b2d 0%, #0b0f19 55%);
        color: #e8eef7;
        font-family: 'Inter', sans-serif;
    }
    h1, h2, h3 { font-family: 'Inter', sans-serif; letter-spacing: -0.02em; }
    .block-container { padding-top: 1.2rem; }

    div[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0e1422 0%, #0b0f19 100%);
        border-right: 1px solid #1c2538;
    }

    .hero {
        background: linear-gradient(135deg, #1a2236 0%, #121826 60%, #1a1020 100%);
        border: 1px solid #2a3550;
        border-left: 4px solid #e94560;
        border-radius: 14px;
        padding: 1.4rem 1.6rem;
        margin-bottom: 1.2rem;
        box-shadow: 0 12px 40px rgba(0,0,0,0.35);
    }
    .hero h1 {
        margin: 0;
        font-size: 1.8rem;
        background: linear-gradient(90deg, #e94560, #f5a623, #4a90d9);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .hero p { color: #9aa8c0; margin: 0.4rem 0 0 0; }

    .metric-card {
        background: #121826;
        border: 1px solid #243049;
        border-radius: 12px;
        padding: 1rem 1.1rem;
        text-align: center;
    }
    .metric-card .label { color: #8b98b0; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em; }
    .metric-card .value { font-size: 1.6rem; font-weight: 700; margin-top: 0.25rem; font-family: 'JetBrains Mono', monospace; }
    .risk-low .value { color: #2ecc71; }
    .risk-medium .value { color: #f5a623; }
    .risk-high .value { color: #e67e22; }
    .risk-critical .value { color: #e94560; }

    .log-box {
        background: #0a0e17;
        border: 1px solid #1c2538;
        border-radius: 10px;
        padding: 0.8rem 1rem;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.78rem;
        color: #9ad07b;
        max-height: 260px;
        overflow-y: auto;
        white-space: pre-wrap;
    }

    .stButton > button {
        background: linear-gradient(90deg, #e94560, #c23a51);
        color: white;
        border: none;
        border-radius: 10px;
        font-weight: 600;
        padding: 0.55rem 1.2rem;
        width: 100%;
    }
    .stButton > button:hover {
        background: linear-gradient(90deg, #ff5a75, #e94560);
        color: white;
        border: none;
    }

    div[data-testid="stDataFrame"] { border: 1px solid #243049; border-radius: 10px; }
    .stTabs [data-baseweb="tab-list"] { gap: 8px; }
    .stTabs [data-baseweb="tab"] {
        background: #121826;
        border-radius: 8px;
        padding: 0.4rem 1rem;
        border: 1px solid #243049;
    }
    .stTabs [aria-selected="true"] {
        background: #1a2236;
        border-color: #e94560;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

def _init_state() -> None:
    defaults = {
        "report": None,
        "logs": [],
        "running": False,
        "exports": {},
        "api_key": os.environ.get("SERPAPI_API_KEY")
        or os.environ.get("SERP_API_KEY")
        or "",
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


_init_state()


# ---------------------------------------------------------------------------
# Sidebar — configuration
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("### ⚙️ Configuration")
    api_key = st.text_input(
        "SerpApi API Key",
        value=st.session_state["api_key"],
        type="password",
        help="Get a key at https://serpapi.com/ — also reads SERPAPI_API_KEY env var.",
        placeholder="serp_xxxxxxxx",
    )
    st.session_state["api_key"] = api_key

    st.markdown("---")
    st.markdown("### 🎯 Target")
    target = st.text_input(
        "Target",
        placeholder="email, phone, name, username…",
        help="Primary investigation subject. Exact-match filtered against every hit.",
    )
    image_url = st.text_input(
        "Image URL (Google Lens)",
        placeholder="https://…/avatar.jpg",
        help="Optional. Enables reverse-image search for catfish / reused avatars.",
    )
    target_type = st.selectbox(
        "Target type",
        options=["auto", "email", "phone", "name", "username", "image", "address", "url"],
        index=0,
    )

    st.markdown("---")
    st.markdown("### 🛰️ Modules")
    col_a, col_b = st.columns(2)
    with col_a:
        use_web = st.checkbox("Web Dorks", value=True)
        use_news = st.checkbox("News", value=True)
    with col_b:
        use_maps = st.checkbox("Maps", value=True)
        use_lens = st.checkbox("Lens", value=bool(image_url))

    st.markdown("---")
    st.markdown("### ⚡ Performance")
    max_workers = st.slider("Concurrent workers", 1, 8, 4)
    num_per_query = st.slider("Results per query", 5, 20, 10)
    include_visuals = st.checkbox("Generate graph + map", value=True)

    st.markdown("---")
    run_clicked = st.button("🚀 Run Investigation", type="primary", use_container_width=True)

    st.markdown(
        "<div style='color:#6b7a94;font-size:0.75rem;margin-top:1.5rem;'>"
        "All data sourced exclusively via <b>SerpApi</b>. "
        "Hits without an exact target match are discarded."
        "</div>",
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Hero header
# ---------------------------------------------------------------------------

st.markdown(
    """
    <div class="hero">
      <h1>🕵️ OSINT Framework</h1>
      <p>Multi-engine SerpApi intelligence · Anti-false-positive filtering ·
         Threat scoring · STIX 2.1 enterprise export</p>
    </div>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

def _append_log(msg: str) -> None:
    st.session_state["logs"].append(f"{time.strftime('%H:%M:%S')}  {msg}")


if run_clicked:
    if not api_key:
        st.error("SerpApi API key is required. Enter it in the sidebar or set SERPAPI_API_KEY.")
    elif not target and not image_url:
        st.error("Provide a target and/or an image URL.")
    else:
        modules: List[str] = []
        if use_web:
            modules.append("web")
        if use_news:
            modules.append("news")
        if use_maps:
            modules.append("maps")
        if use_lens or image_url:
            modules.append("lens")
        if not modules:
            modules = ["web"]

        st.session_state["logs"] = []
        st.session_state["running"] = True
        st.session_state["report"] = None
        st.session_state["exports"] = {}

        status = st.status("Running multi-engine investigation…", expanded=True)
        log_area = st.empty()

        def progress_cb(msg: str) -> None:
            _append_log(msg)
            # Refresh live log (last 40 lines)
            log_area.markdown(
                "<div class='log-box'>"
                + "\n".join(st.session_state["logs"][-40:]).replace("<", "&lt;")
                + "</div>",
                unsafe_allow_html=True,
            )
            status.write(msg)

        try:
            with status:
                report = run_investigation(
                    target=target or image_url or "",
                    api_key=api_key,
                    modules=modules,
                    target_type=target_type,
                    image_url=image_url or None,
                    max_workers=max_workers,
                    num_per_query=num_per_query,
                    progress_callback=progress_cb,
                    export=True,
                    include_visuals=include_visuals,
                )
            st.session_state["report"] = report
            st.session_state["exports"] = report.metadata.get("exports") or {}
            status.update(
                label=f"Complete — score {report.threat.score}/100 ({report.threat.level.value})",
                state="complete",
                expanded=False,
            )
            st.success(
                f"Investigation finished. "
                f"{report.metadata.get('deduped_hits', 0)} validated hits · "
                f"{len(report.entities)} entities · "
                f"score {report.threat.score}/100"
            )
        except Exception as exc:
            status.update(label="Investigation failed", state="error")
            st.exception(exc)
        finally:
            st.session_state["running"] = False


# ---------------------------------------------------------------------------
# Results view
# ---------------------------------------------------------------------------

report: InvestigationReport = st.session_state.get("report")

if report is None:
    st.info(
        "Configure a target in the sidebar and hit **Run Investigation**. "
        f"Detected type preview updates live once you type a target."
    )
    if target:
        st.caption(f"Auto-detected type for `{target}` → **{detect_target_type(target)}**")
    st.stop()


# ---- Metric strip ----
hits = report.deduplicated_results()
level = report.threat.level.value if hasattr(report.threat.level, "value") else str(report.threat.level)
risk_class = f"risk-{level.lower()}"

c1, c2, c3, c4, c5 = st.columns(5)
cards = [
    (c1, "Validated Hits", str(len(hits)), ""),
    (c2, "Entities", str(len(report.entities)), ""),
    (c3, "Queries", str(len(report.attempted_queries)), ""),
    (c4, "Threat Score", f"{report.threat.score}/100", risk_class),
    (c5, "Risk Level", level, risk_class),
]
for col, label, value, extra in cards:
    with col:
        st.markdown(
            f"<div class='metric-card {extra}'>"
            f"<div class='label'>{label}</div>"
            f"<div class='value'>{value}</div></div>",
            unsafe_allow_html=True,
        )

st.markdown("")
st.markdown(f"**Assessment:** {report.threat.summary}")

if report.threat.factors:
    with st.expander("Contributing risk factors", expanded=False):
        for f in report.threat.factors:
            st.markdown(f"- {f}")


# ---- Tabs ----
tab_results, tab_entities, tab_queries, tab_graph, tab_map, tab_exports, tab_logs = st.tabs(
    [
        "📋 Results",
        "🧬 Entities",
        "🔍 Queries",
        "🕸️ Graph",
        "🗺️ Map",
        "📦 Exports",
        "📜 Live Log",
    ]
)

with tab_results:
    if not hits:
        st.warning(
            "Zero validated records after anti-false-positive filtering. "
            "See the **Queries** tab for the full attempt audit (Zero Records section)."
        )
    else:
        try:
            import pandas as pd

            rows = []
            for r in hits:
                rows.append(
                    {
                        "Title": r.title,
                        "Link": r.link,
                        "Snippet": r.snippet,
                        "Source": r.source,
                        "Engine": r.engine,
                        "Module": r.module,
                        "Phone": r.phone,
                        "Address": r.address,
                        "Lat": r.latitude,
                        "Lon": r.longitude,
                        "Date": r.date,
                    }
                )
            df = pd.DataFrame(rows)
            st.dataframe(df, use_container_width=True, height=420)
        except Exception:
            for r in hits[:50]:
                st.markdown(f"**{r.title}**  \n{r.link}  \n_{r.snippet}_")

with tab_entities:
    if not report.entities:
        st.info("No secondary entities extracted from snippets.")
    else:
        try:
            import pandas as pd

            edf = pd.DataFrame([e.to_dict() for e in report.entities])
            st.dataframe(edf, use_container_width=True, height=360)
        except Exception:
            for e in report.entities:
                st.markdown(f"- `{e.entity_type}` **{e.value}** — {e.context}")

with tab_queries:
    st.markdown("#### Full query audit (includes Zero Records)")
    zero = [
        q
        for q in report.attempted_queries
        if q.filtered_count == 0 or q.status in {"empty", "error"}
    ]
    st.caption(
        f"{len(report.attempted_queries)} total · "
        f"{len(zero)} with zero validated hits / errors"
    )
    try:
        import pandas as pd

        qdf = pd.DataFrame([q.to_dict() for q in report.attempted_queries])
        st.dataframe(qdf, use_container_width=True, height=360)
    except Exception:
        for q in report.attempted_queries:
            st.code(f"[{q.status}] {q.engine} raw={q.result_count} kept={q.filtered_count} :: {q.query}")

with tab_graph:
    exports = st.session_state.get("exports") or {}
    graph_path = exports.get("graph")
    if graph_path and Path(graph_path).exists():
        html = Path(graph_path).read_text(encoding="utf-8")
        st.components.v1.html(html, height=780, scrolling=True)
        st.caption(f"Source: `{graph_path}`")
    else:
        st.info("No graph generated for this run (no visuals or empty graph).")
        if st.button("Generate graph now"):
            try:
                from osint_framework.visualizer import build_network_graph

                path = build_network_graph(report)
                st.session_state["exports"]["graph"] = path
                st.rerun()
            except Exception as exc:
                st.error(str(exc))

with tab_map:
    exports = st.session_state.get("exports") or {}
    map_path = exports.get("map")
    # Prefer live folium rendering when coordinates exist
    coords = [
        (r.latitude, r.longitude, r)
        for r in hits
        if r.latitude is not None and r.longitude is not None
    ]
    if coords:
        try:
            import folium
            from folium.plugins import MarkerCluster
            from streamlit_folium import st_folium

            mean_lat = sum(c[0] for c in coords) / len(coords)
            mean_lon = sum(c[1] for c in coords) / len(coords)
            fmap = folium.Map(
                location=[mean_lat, mean_lon],
                zoom_start=4 if len(coords) > 1 else 12,
                tiles="OpenStreetMap",
            )
            cluster = MarkerCluster().add_to(fmap)
            for lat, lon, r in coords:
                folium.Marker(
                    [lat, lon],
                    popup=f"<b>{r.title}</b><br>{r.address or ''}<br>{r.phone or ''}",
                    tooltip=r.title or r.address or "hit",
                    icon=folium.Icon(color="red", icon="info-sign"),
                ).add_to(cluster)
            st_folium(fmap, width=None, height=600)
        except Exception as exc:
            st.warning(f"Live map render failed ({exc}); falling back to saved HTML.")
            if map_path and Path(map_path).exists():
                st.components.v1.html(
                    Path(map_path).read_text(encoding="utf-8"), height=600, scrolling=True
                )
    elif map_path and Path(map_path).exists():
        st.components.v1.html(
            Path(map_path).read_text(encoding="utf-8"), height=600, scrolling=True
        )
    else:
        st.info("No geospatial coordinates discovered for this target.")

with tab_exports:
    exports = st.session_state.get("exports") or report.metadata.get("exports") or {}
    if not exports:
        st.info("No exports on file.")
    else:
        for kind, path in exports.items():
            if not path:
                continue
            p = Path(path)
            st.markdown(f"**{kind.upper()}** — `{p}`")
            if p.exists():
                data = p.read_bytes()
                mime = {
                    "json": "application/json",
                    "csv": "text/csv",
                    "txt": "text/plain",
                    "stix": "application/json",
                    "graph": "text/html",
                    "map": "text/html",
                }.get(kind, "application/octet-stream")
                st.download_button(
                    label=f"Download {p.name}",
                    data=data,
                    file_name=p.name,
                    mime=mime,
                    key=f"dl_{kind}_{p.name}",
                )
            st.markdown("---")

with tab_logs:
    logs = st.session_state.get("logs") or []
    if not logs:
        st.caption("No logs yet.")
    else:
        st.markdown(
            "<div class='log-box'>"
            + "\n".join(logs).replace("<", "&lt;")
            + "</div>",
            unsafe_allow_html=True,
        )
