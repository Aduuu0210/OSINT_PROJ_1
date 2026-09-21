# OSINT Framework — SerpApi Powered

Next-generation **Open Source Intelligence** toolkit for identifying scammers and persons of interest. Every external lookup is routed exclusively through the [SerpApi](https://serpapi.com/) ecosystem (Google, Google News, Google Maps, Google Lens).

## Highlights

| Capability | Implementation |
|---|---|
| Anti-false-positive filter | `is_valid_hit(target, result)` — exact target must appear in title/snippet/URL |
| Multi-engine modules | Web dorks · News · Maps · Lens |
| Concurrency | `ThreadPoolExecutor` + exponential backoff on rate limits |
| Graceful empty handling | `"Google hasn't returned any results…"` → `[]` + `[INFO]` log, never crash |
| NER / entity extraction | Emails, phones, BTC/ETH/XMR wallets, IPs, social handles |
| Dynamic threat score | 0–100 → Low / Medium / High / Critical |
| Visuals | `pyvis` force-directed graph · `folium` geospatial map |
| Enterprise exports | JSON · CSV · TXT executive summary · **STIX 2.1** bundle |
| UI | Dark-mode **Streamlit** dashboard |

## Project layout

```
OSINT_PROJ_1/
├── requirements.txt
├── README.md
├── run_ui.sh               # WSL/Linux/macOS launcher
├── scripts/
│   └── smoke_test.py       # offline end-to-end verification (no API key)
└── osint_framework/
    ├── __init__.py
    ├── main.py              # CLI entry point
    ├── app.py               # Streamlit dashboard
    ├── serpapi_client.py    # API client + concurrency
    ├── models.py            # Data classes + is_valid_hit
    ├── analytics.py         # NER + threat scoring
    ├── visualizer.py        # Graph + map
    ├── reporter.py          # JSON/CSV/TXT/STIX exports
    ├── modules/
    │   ├── web_dorks.py     # engine=google
    │   ├── news_search.py   # engine=google_news
    │   ├── maps_search.py   # engine=google_maps
    │   └── lens_search.py   # engine=google_lens
    └── reports/             # osint_report_<timestamp>.*
```

## Quick start

```bash
# 1. Install
cd OSINT_PROJ_1
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 2. Configure key
export SERPAPI_API_KEY="your_key_here"

# 3a. CLI investigation
python -m osint_framework.main -t "suspect@example.com" --modules web,news,maps

# 3b. With reverse-image (catfish) pivot
python -m osint_framework.main -t "Jane Doe" \
  --image-url "https://example.com/avatar.jpg" \
  --modules web,news,maps,lens

# 3c. Interactive dashboard
./run_ui.sh
# or:
python -m osint_framework.main --ui
# or:
streamlit run osint_framework/app.py --server.address 0.0.0.0 --server.headless true
```

### Running on WSL (Windows Subsystem for Linux)

WSL cannot auto-open a browser and inotify file-watching is unreliable, so the
repo ships WSL-safe Streamlit defaults in `.streamlit/config.toml`
(`headless = true`, `address = "0.0.0.0"`, `fileWatcherType = "poll"`).

```bash
cd <repo-root>                      # the folder that contains osint_framework/
pip install -r requirements.txt
./run_ui.sh                          # sets PYTHONPATH + WSL-safe flags for you
```

Then open **http://localhost:8501** in your Windows browser.

If you see `ModuleNotFoundError: osint_framework`, make sure you're in the repo
root and run `export PYTHONPATH="$(pwd):$PYTHONPATH"` before launching.

## CLI reference

```
python -m osint_framework.main \
  --target "..." \
  --api-key "$SERPAPI_API_KEY" \
  --modules web,news,maps,lens \
  --target-type auto \
  --image-url https://... \
  --max-workers 4 \
  --num 10 \
  --output-dir ./osint_framework/reports \
  -v
```

| Flag | Purpose |
|---|---|
| `-t / --target` | Email, phone, name, username, URL |
| `--image-url` | Google Lens reverse-image input |
| `--modules` | `web`, `news`, `maps`, `lens` |
| `--no-export` | Skip writing report files |
| `--no-visuals` | Skip graph/map generation |
| `--ui` | Launch Streamlit |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Investigation completed; every query succeeded |
| `1` | Unhandled failure during the run |
| `2` | Usage error (no target, or no API key) |
| `3` | **Report is incomplete** — one or more queries failed (invalid/expired key, exhausted quota, network). Never treat this run as a clean result. |

## Incomplete-collection guard

A threat score of `0` only means "nothing incriminating found" **if the searches
actually ran**. When queries fail — an invalid or expired API key, an exhausted
quota, a network drop — the framework refuses to present the run as a clean
assessment, because that is a false negative an analyst would act on.

When any query errors:

- `report.threat.summary` is rewritten to `No conclusion can be drawn …` and
  states how many queries failed and why
- a leading `Investigation incomplete: N/M queries failed.` risk factor is added
- `report.metadata` carries `collection_incomplete`, `errored_queries`,
  `total_queries` and `errors`
- the dashboard shows a red **Coverage warning** banner and switches the
  zero-results message from "filtered out" to "most engines never returned data"
- exported TXT/JSON/STIX reports carry the same warning as the UI
- the CLI prints a `WARNING` block and exits `3`

Per-query errors are always visible in the **Queries** tab
(`status` + `error_message`) and the report's Zero Records audit section.

## Verification

An offline smoke test exercises the real pipeline, the integrity guard, the CLI
exit codes and the Streamlit UI. It stubs only the SerpApi network transport, so
it needs **no API key** and makes **no outbound requests**:

```bash
pip install -r requirements.txt
python scripts/smoke_test.py     # exits 0 when all checks pass
```

Run it after any change to `main.py`, `app.py`, `models.py` or the modules, and
after bumping a dependency ceiling in `requirements.txt`.

## Anti-false-positive contract

Every SerpApi organic / news / maps / lens row is discarded unless
`models.is_valid_hit(target, result_dict)` confirms the target string
(case-insensitive, with phone/email variants) appears in the title,
snippet, URL, address, or phone fields. This is non-negotiable.

## Threat scoring (0–100)

| Signal | Weight |
|---|---|
| Paste / dump sites (pastebin, rentry, …) | +25 / host (cap 40) |
| Scam / complaint boards | +20 / host (cap 40) |
| Exposed PDFs / docs | +10 each (cap 20) |
| Breach / dump language | +15…30 |
| Dark-web language | +20 |
| Crypto wallets extracted | +10…20 |
| Expanded contact surface | +5 |
| Large public footprint | +5…10 |

Levels: **Low** (0–24) · **Medium** (25–49) · **High** (50–74) · **Critical** (75–100).

## Reports

All artifacts share a timestamp and land in `osint_framework/reports/`:

```
osint_report_YYYYMMDD_HHMMSS.json
osint_report_YYYYMMDD_HHMMSS.csv
osint_report_YYYYMMDD_HHMMSS.txt          # executive summary + Zero Records section
osint_report_YYYYMMDD_HHMMSS_stix.json    # STIX 2.1 bundle for TIP ingestion
osint_report_YYYYMMDD_HHMMSS_graph.html   # pyvis network
osint_report_YYYYMMDD_HHMMSS_map.html     # folium map
```

The TXT report always includes a **ZERO RECORDS DISCOVERED** section listing
every query that returned nothing (or was fully filtered), so negative results
are auditable.

## Disclaimer

This framework only queries **public** indexes via SerpApi. It is intended for
legitimate security research, fraud investigation, and defensive OSINT. Always
corroborate findings before operational, legal, or HR action. Respect applicable
laws and SerpApi's terms of service.
