"""
Visualization engine: force-directed entity graphs (pyvis/networkx) and
geospatial maps (folium).
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .models import ExtractedEntity, InvestigationReport, OSINTResult

logger = logging.getLogger("osint.visualizer")


def _reports_dir(base: Optional[Union[str, Path]] = None) -> Path:
    if base:
        p = Path(base)
    else:
        p = Path(__file__).resolve().parent / "reports"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _safe(s: str, limit: int = 48) -> str:
    s = (s or "").strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


# ---------------------------------------------------------------------------
# Force-directed graph
# ---------------------------------------------------------------------------

def build_network_graph(
    report: InvestigationReport,
    *,
    output_path: Optional[Union[str, Path]] = None,
    height: str = "750px",
    width: str = "100%",
) -> str:
    """
    Generate an interactive HTML force-directed graph:

        Target -> Emails / Phones / Social / Docs / Domains -> individual hits

    Returns the path to the written HTML file.
    """
    try:
        import networkx as nx
        from pyvis.network import Network
    except ImportError as exc:
        raise RuntimeError(
            "pyvis and networkx are required for graph visualization. "
            "pip install pyvis networkx"
        ) from exc

    results = report.deduplicated_results()
    entities = report.entities or []

    G = nx.Graph()
    target = report.target
    G.add_node(
        "TARGET",
        label=_safe(target, 40),
        title=f"Target: {target}",
        group="target",
        size=40,
        color="#e94560",
    )

    # Category hub nodes
    hubs = {
        "email": ("Emails", "#0f9d8a"),
        "phone": ("Phones", "#f5a623"),
        "social": ("Social Handles", "#4a90d9"),
        "btc": ("BTC Wallets", "#f7931a"),
        "eth": ("ETH Wallets", "#627eea"),
        "xmr": ("XMR Wallets", "#ff6600"),
        "ip": ("IP Addresses", "#9b59b6"),
        "doc": ("Exposed Documents", "#c0392b"),
        "news": ("News / Press", "#1abc9c"),
        "maps": ("Maps / Places", "#2ecc71"),
        "web": ("Web Hits", "#95a5a6"),
        "paste": ("Paste / Dumps", "#e74c3c"),
        "scam": ("Scam Boards", "#8e44ad"),
    }

    def ensure_hub(key: str) -> str:
        node_id = f"hub:{key}"
        if node_id not in G:
            label, color = hubs.get(key, (key.title(), "#7f8c8d"))
            G.add_node(
                node_id,
                label=label,
                title=label,
                group="hub",
                size=28,
                color=color,
            )
            G.add_edge("TARGET", node_id, title="pivot")
        return node_id

    # Entity nodes
    for ent in entities:
        hub = ensure_hub(ent.entity_type if ent.entity_type in hubs else "web")
        nid = f"ent:{ent.entity_type}:{ent.value}"
        if nid not in G:
            G.add_node(
                nid,
                label=_safe(ent.value, 36),
                title=f"{ent.entity_type}: {ent.value}\n{ent.context}",
                group=ent.entity_type,
                size=18,
                color=hubs.get(ent.entity_type, ("", "#7f8c8d"))[1],
            )
            G.add_edge(hub, nid, title=ent.entity_type)

    # Result nodes — bucket by module / host signal
    paste_hosts = ("pastebin", "paste.ee", "rentry", "justpaste", "ghostbin", "dpaste")
    scam_hosts = ("scamwatcher", "scamadviser", "ripoffreport", "800notes", "scamdoc")
    doc_exts = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".sql")

    for i, r in enumerate(results[:150]):  # cap for readability
        link = r.link or ""
        lower_link = link.lower()
        module = (r.module or "").lower()

        if any(h in lower_link for h in paste_hosts):
            bucket = "paste"
        elif any(h in lower_link for h in scam_hosts):
            bucket = "scam"
        elif any(lower_link.endswith(ext) or ext in lower_link for ext in doc_exts):
            bucket = "doc"
        elif "news" in module:
            bucket = "news"
        elif "maps" in module:
            bucket = "maps"
        elif "lens" in module:
            bucket = "social"
        else:
            bucket = "web"

        hub = ensure_hub(bucket)
        nid = f"hit:{i}"
        label = _safe(r.title or r.source or link, 40)
        title_tt = f"{r.title}\n{r.snippet[:180]}\n{link}\nengine={r.engine}"
        G.add_node(
            nid,
            label=label,
            title=title_tt,
            group=bucket,
            size=12,
            color=hubs.get(bucket, ("", "#95a5a6"))[1],
        )
        G.add_edge(hub, nid, title=r.engine)

        # Link hit → entities mentioned in its snippet
        blob = f"{r.title} {r.snippet} {r.link}".lower()
        for ent in entities:
            if ent.value.lower() in blob:
                ent_id = f"ent:{ent.entity_type}:{ent.value}"
                if ent_id in G:
                    G.add_edge(nid, ent_id, title="mentions")

    # Render with pyvis
    net = Network(
        height=height,
        width=width,
        bgcolor="#0b0f19",
        font_color="#e8eef7",
        directed=False,
        notebook=False,
    )
    net.barnes_hut(
        gravity=-12000,
        central_gravity=0.3,
        spring_length=140,
        spring_strength=0.02,
        damping=0.4,
    )
    net.from_nx(G)
    net.set_options(
        """
        var options = {
          "nodes": {
            "borderWidth": 1,
            "borderWidthSelected": 2,
            "font": {"size": 14, "face": "Inter, Segoe UI, sans-serif"}
          },
          "edges": {
            "color": {"color": "#2a3550", "highlight": "#e94560"},
            "smooth": {"type": "dynamic"}
          },
          "physics": {"stabilization": {"iterations": 120}},
          "interaction": {
            "hover": true,
            "tooltipDelay": 120,
            "navigationButtons": true,
            "keyboard": true
          }
        }
        """
    )

    out = Path(output_path) if output_path else _reports_dir() / f"osint_report_{_ts()}_graph.html"
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)

    # pyvis write_html with notebook=False
    net.write_html(str(out), open_browser=False, notebook=False)
    logger.info("Wrote graph visualization → %s", out)
    return str(out)


# ---------------------------------------------------------------------------
# Geospatial map
# ---------------------------------------------------------------------------

def build_folium_map(
    report: InvestigationReport,
    *,
    output_path: Optional[Union[str, Path]] = None,
) -> Optional[str]:
    """
    Plot discovered coordinates / addresses on an interactive Folium map.
    Returns output path, or None if there is nothing to plot.
    """
    try:
        import folium
        from folium.plugins import MarkerCluster
    except ImportError as exc:
        raise RuntimeError(
            "folium is required for map visualization. pip install folium"
        ) from exc

    points: List[Dict[str, Any]] = []
    for r in report.deduplicated_results():
        if r.latitude is not None and r.longitude is not None:
            points.append(
                {
                    "lat": float(r.latitude),
                    "lon": float(r.longitude),
                    "title": r.title or r.address or report.target,
                    "address": r.address,
                    "phone": r.phone,
                    "link": r.link,
                    "snippet": r.snippet,
                }
            )

    if not points:
        logger.info("No geospatial points to plot.")
        return None

    # Center on mean lat/lon
    mean_lat = sum(p["lat"] for p in points) / len(points)
    mean_lon = sum(p["lon"] for p in points) / len(points)

    # Use built-in OSM tiles (no third-party API key). Dark styling via optional attr.
    fmap = folium.Map(
        location=[mean_lat, mean_lon],
        zoom_start=4 if len(points) > 1 else 12,
        tiles="OpenStreetMap",
    )
    # Secondary dark-ish layer when available without a key
    try:
        folium.TileLayer(
            tiles="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
            attr='&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> '
                 '&copy; <a href="https://carto.com/attributions">CARTO</a>',
            name="Dark Matter",
            overlay=False,
            control=True,
        ).add_to(fmap)
    except Exception:
        pass
    cluster = MarkerCluster(name="OSINT Hits").add_to(fmap)

    for p in points:
        popup_html = (
            f"<b>{_safe(p['title'], 80)}</b><br>"
            f"{_safe(p.get('address') or '', 100)}<br>"
            f"{_safe(p.get('phone') or '', 40)}<br>"
            f"<a href='{p.get('link') or '#'}' target='_blank'>Open</a>"
        )
        folium.Marker(
            location=[p["lat"], p["lon"]],
            popup=folium.Popup(popup_html, max_width=320),
            tooltip=_safe(p["title"], 60),
            icon=folium.Icon(color="red", icon="info-sign"),
        ).add_to(cluster)

    folium.LayerControl().add_to(fmap)

    # Target marker legend via a caption
    title_html = f"""
    <div style="position:fixed;top:12px;left:60px;z-index:9999;
                background:#0b0f19;color:#e8eef7;padding:8px 14px;
                border:1px solid #e94560;border-radius:8px;font-family:sans-serif;">
      <b>OSINT Map</b> — { _safe(report.target, 40) } ({len(points)} pins)
    </div>
    """
    fmap.get_root().html.add_child(folium.Element(title_html))

    out = Path(output_path) if output_path else _reports_dir() / f"osint_report_{_ts()}_map.html"
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    fmap.save(str(out))
    logger.info("Wrote map visualization → %s", out)
    return str(out)


def generate_all_visuals(
    report: InvestigationReport,
    *,
    output_dir: Optional[Union[str, Path]] = None,
    stamp: Optional[str] = None,
) -> Dict[str, Optional[str]]:
    """Build graph + map with a shared timestamp prefix."""
    stamp = stamp or _ts()
    out_dir = _reports_dir(output_dir)
    prefix = out_dir / f"osint_report_{stamp}"

    graph_path = build_network_graph(
        report, output_path=str(prefix) + "_graph.html"
    )
    map_path = build_folium_map(
        report, output_path=str(prefix) + "_map.html"
    )
    return {"graph": graph_path, "map": map_path}
