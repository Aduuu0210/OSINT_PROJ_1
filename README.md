# OSINT Framework — SerpApi Powered

Next-generation **Open Source Intelligence** toolkit for identifying scammers and
persons of interest. Every external lookup is routed exclusively through the
[SerpApi](https://serpapi.com/) ecosystem (Google, Google News, Google Maps,
Google Lens).

Give it an email, phone number, name, username or photo. It searches four Google
engines, throws away anything that doesn't actually mention your target, extracts
the emails/phones/crypto wallets it finds, scores the exposure 0–100, and writes
JSON / CSV / TXT / STIX 2.1 reports plus a network graph and a map.

---

## Contents

1. [Prerequisites](#prerequisites)
2. [Quick start (5 minutes)](#quick-start-5-minutes)
3. [Verify your install](#verify-your-install)
4. [Run your first investigation](#run-your-first-investigation)
5. [Reading your results](#reading-your-results)
6. [Troubleshooting](#troubleshooting)
7. [Exit codes](#exit-codes)
8. [Incomplete-collection guard](#incomplete-collection-guard)
9. [Reference](#reference)
10. [Extending the framework](#extending-the-framework)
11. [Getting help](#getting-help)
12. [Disclaimer](#disclaimer)

---

## Prerequisites

| Requirement | Notes |
|---|---|
| **Python 3.11+** | Verified on 3.11.2. Check with `python --version`. |
| **A SerpApi key** | Free tier available at <https://serpapi.com/> → *Dashboard → API Key*. No credit card needed for the free plan. |
| **~500 MB disk** | For the virtualenv and generated reports. |

You do **not** need a key to install the project or run the verification suite
(see [Verify your install](#verify-your-install)).

---

## Quick start (5 minutes)

### 1. Clone and enter the repo

```bash
git clone https://github.com/Aduuu0210/OSINT_PROJ_1.git
cd OSINT_PROJ_1
```

> **Important:** every command in this README assumes you are in the **repo
> root** — the folder that *contains* `osint_framework/`, not inside it.

### 2. Create a virtualenv and install

```bash
python -m venv .venv

# Linux / macOS / WSL
source .venv/bin/activate

# Windows (PowerShell)
.venv\Scripts\Activate.ps1

# Windows (cmd.exe)
.venv\Scripts\activate.bat

pip install -r requirements.txt
```

`requirements.txt` is pinned with major-version ceilings, so a fresh install
reproduces the environment this code was verified against.

### 3. Set your API key

```bash
# Linux / macOS / WSL
export SERPAPI_API_KEY="your_key_here"

# Windows PowerShell
$env:SERPAPI_API_KEY = "your_key_here"

# Windows cmd.exe
set SERPAPI_API_KEY=your_key_here
```

Get the key from <https://serpapi.com/dashboard>. Setting it as an environment
variable means you never have to type it again — the CLI and the dashboard both
read it automatically.

### 4. Launch the dashboard

```bash
./run_ui.sh                                  # Linux / macOS / WSL
python -m osint_framework.main --ui          # any OS
```

Then open **http://localhost:8501** in your browser.

---

## Verify your install

Run this **before** your first real investigation. It checks the whole pipeline
end to end and needs **no API key** and **no internet access**:

```bash
python scripts/smoke_test.py
```

Expected output:

```
  PASS  package imports resolve
  PASS  target classification handles hostile input
  PASS  anti-false-positive filter rejects non-matching hits
  PASS  successful run: hits, exports, no false alarm
  PASS  total API failure never reports a clean result
  PASS  CLI exit codes: 0 clean, 2 usage, 3 incomplete
  PASS  failed/succeeded query counters can never contradict
  PASS  Streamlit UI renders with no exceptions
  PASS  UI surfaces the incomplete-collection warning
  PASS  UI full journey: form -> run -> results
10 passed, 0 failed, 10 total
```

Exit code `0` means everything passed. If any line says `FAIL`, see
[Troubleshooting](#troubleshooting) — and please include the full output when
you report it.

Re-run it any time you change `main.py`, `app.py`, `models.py` or a module, and
after bumping a dependency in `requirements.txt`.

---

## Run your first investigation

### Option A — the dashboard (recommended)

`./run_ui.sh`, then in the sidebar:

1. **SerpApi API Key** — pre-filled from `SERPAPI_API_KEY` if you set it
2. **Target** — e.g. `suspect@example.com`
3. **Modules** — leave Web / News / Maps on; enable **Lens** only with an image URL
4. Click **🚀 Run Investigation**

Live progress appears in the status panel and the **Live Log** tab.

### Option B — the CLI

```bash
# Simple email investigation
python -m osint_framework.main -t "suspect@example.com" --modules web,news,maps

# Phone number
python -m osint_framework.main -t "+1 415-555-0100"

# Reverse-image (catfish / reused avatar) pivot
python -m osint_framework.main -t "Jane Doe" \
  --image-url "https://example.com/avatar.jpg" \
  --modules web,news,maps,lens

# Verbose logging, custom output folder
python -m osint_framework.main -t "suspect@example.com" -v --output-dir ./reports
```

A successful run ends with a summary block:

```
================================================================
 TARGET : suspect@example.com
 TYPE   : email
 HITS   : 14
 ENTITIES: 6
 THREAT : 40/100  [Medium]
 SUMMARY: Threat score 40/100 (Medium) for 'suspect@example.com'. ...
 EXPORTS:
   - json: osint_framework/reports/osint_report_20260921_162250.json
   - csv:  osint_framework/reports/osint_report_20260921_162250.csv
   ...
================================================================
```

### How many API credits does a run use?

One SerpApi credit per query. The count depends on the target *type*, because
each type generates a different query set. Measured values:

| Modules | Email target | Phone target | Name target |
|---|---|---|---|
| `web` | 18 | 18 | 16 |
| `web,news` | 23 | 21 | 19 |
| `web,news,maps` | 25 | 24 | 22 |
| `web,news,maps,lens` | 26 | 23 | 21 |

So a typical three-module run costs **~22–25 credits**. The free SerpApi tier is
100 searches/month — roughly four investigations — so budget accordingly.

The exact count for your run is printed as `api_calls` in the log and recorded in
`report.metadata["api_calls"]`; every individual query is listed in the
**Queries** tab.

---

## Reading your results

### Threat score

| Score | Level | What it means |
|---|---|---|
| 0–24 | **Low** | No strong public exposure signals |
| 25–49 | **Medium** | Some exposure — worth reviewing the hits |
| 50–74 | **High** | Multiple risk signals present |
| 75–100 | **Critical** | Strong indicators; corroborate before acting |

**A low score is not a clean bill of health.** It only means the searches that
*ran* found nothing incriminating — see
[Incomplete-collection guard](#incomplete-collection-guard).

### Dashboard tabs

| Tab | What to look at |
|---|---|
| 📋 **Results** | Every validated hit. If empty, read the banner — it says whether hits were filtered out or the engines never answered. |
| 🧬 **Entities** | Emails, phones, crypto wallets, IPs and handles extracted from snippets. These are your pivot points for a follow-up run. |
| 🔍 **Queries** | Full audit of every query, including ones that returned nothing or errored (`status`, `result_count`, `filtered_count`, `error_message`). |
| 🕸️ **Graph** | Interactive network linking the target to entities and hits. |
| 🗺️ **Map** | Geospatial cluster, when any hit carried coordinates. |
| 📦 **Exports** | Download buttons for every generated artifact. |
| 📜 **Live Log** | Timestamped run log — the first place to look when something looks wrong. |

### Suggested follow-up workflow

1. Run the target as given.
2. Open **Entities** and note any *new* email, phone or handle.
3. Re-run each of those as a fresh target — that's how a thin first result
   becomes a real picture.
4. Keep the `Queries` tab open: a zero-result run is only meaningful if every
   query actually succeeded.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `SerpApi API key is required` | No key set | Set `SERPAPI_API_KEY`, or paste the key into the sidebar. Get one at <https://serpapi.com/dashboard>. |
| `ModuleNotFoundError: osint_framework` | Not in the repo root | `cd` to the folder containing `osint_framework/`, then `export PYTHONPATH="$(pwd):$PYTHONPATH"` and relaunch. |
| Report says **INCOMPLETE INVESTIGATION** | Invalid/expired key, exhausted quota, or network failure | Read the printed error. Check the key at <https://serpapi.com/dashboard>, confirm you have credits left, then re-run. **Do not treat the report as clean.** |
| `HITS: 0` but all queries `ok` | Anti-false-positive filter discarded everything | Expected when the target has little public footprint. Check the **Queries** tab, then try a broader target type or a different module set. |
| `ModuleNotFoundError` for `streamlit` / `pyvis` / etc. | Dependencies not installed in the active env | Confirm the venv is active (`which python`), then `pip install -r requirements.txt`. |
| Browser doesn't open automatically | Normal on WSL and headless servers | Open **http://localhost:8501** manually. |
| `Port 8501 is not available` | Another instance is running | Stop it, or use another port: `PORT=8502 ./run_ui.sh`. |
| Edits don't hot-reload | inotify unreliable on WSL | Expected — the repo sets `fileWatcherType = "poll"`. Restart the server if needed. |
| `Please replace use_container_width with width` in the log | Streamlit deprecation notice | Cosmetic only; the dashboard still works. Tracked as a known issue. |

### Confirming your environment

```bash
python --version                        # expect 3.11+
python -c "import streamlit; print(streamlit.__version__)"
python -m osint_framework.main --help   # proves the package imports
python scripts/smoke_test.py            # full offline check
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Investigation completed; every query succeeded |
| `1` | Unhandled failure during the run |
| `2` | Usage error (no target, or no API key) |
| `3` | **Report is incomplete** — one or more queries failed (invalid/expired key, exhausted quota, network). Never treat this run as a clean result. |

Use these in scripts and CI: a non-zero exit always means the run needs attention.

---

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

---

## Reference

### Project layout

```
OSINT_PROJ_1/
├── requirements.txt        # pinned dependencies
├── README.md
├── run_ui.sh               # WSL/Linux/macOS launcher
├── scripts/
│   └── smoke_test.py       # offline end-to-end verification (no API key)
└── osint_framework/
    ├── __init__.py
    ├── main.py              # CLI entry point + investigation orchestrator
    ├── app.py               # Streamlit dashboard
    ├── serpapi_client.py    # API client + concurrency + backoff
    ├── models.py            # Data classes + is_valid_hit anti-FP filter
    ├── analytics.py         # NER + threat scoring
    ├── visualizer.py        # pyvis graph + folium map
    ├── reporter.py          # JSON/CSV/TXT/STIX exports
    ├── modules/
    │   ├── web_dorks.py     # engine=google
    │   ├── news_search.py   # engine=google_news
    │   ├── maps_search.py   # engine=google_maps
    │   └── lens_search.py   # engine=google_lens
    └── reports/             # osint_report_<timestamp>.*
```

### CLI flags

| Flag | Default | Purpose |
|---|---|---|
| `-t / --target` | — | Email, phone, name, username, URL |
| `--image-url` | — | Google Lens reverse-image input |
| `--api-key` | `$SERPAPI_API_KEY` | SerpApi key, if not set in the environment |
| `--modules` | `web,news,maps` | Any of `web`, `news`, `maps`, `lens` |
| `--target-type` | `auto` | Force `email`/`phone`/`name`/`username`/`image`/`address`/`url` |
| `--max-workers` | `4` | Concurrent queries |
| `--num` | `10` | Results per Google query |
| `--output-dir` | `osint_framework/reports/` | Where reports are written |
| `--no-export` | off | Skip writing report files |
| `--no-visuals` | off | Skip graph/map generation |
| `--ui` | off | Launch the Streamlit dashboard |
| `-v / --verbose` | off | Debug logging |

### Anti-false-positive contract

Every SerpApi organic / news / maps / lens row is discarded unless
`models.is_valid_hit(target, result_dict)` confirms the target string
(case-insensitive, with phone/email variants) appears in the title,
snippet, URL, address, or phone fields. This is non-negotiable and is the main
reason a run can legitimately return zero hits.

### Threat scoring signals

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

### Report artifacts

All artifacts share one timestamp and land in `osint_framework/reports/`:

```
osint_report_YYYYMMDD_HHMMSS.json
osint_report_YYYYMMDD_HHMMSS.csv
osint_report_YYYYMMDD_HHMMSS.txt          # executive summary + Zero Records section
osint_report_YYYYMMDD_HHMMSS_stix.json    # STIX 2.1 bundle for TIP ingestion
osint_report_YYYYMMDD_HHMMSS_graph.html   # pyvis network
osint_report_YYYYMMDD_HHMMSS_map.html     # folium map (only when coordinates exist)
```

The TXT report always includes a **ZERO RECORDS DISCOVERED** section listing
every query that returned nothing (or was fully filtered), so negative results
are auditable.

### Running on WSL (Windows Subsystem for Linux)

WSL cannot auto-open a browser and inotify file-watching is unreliable, so the
repo ships WSL-safe Streamlit defaults in `.streamlit/config.toml`
(`headless = true`, `address = "0.0.0.0"`, `fileWatcherType = "poll"`).

```bash
cd <repo-root>
./run_ui.sh        # sets PYTHONPATH and the WSL-safe flags for you
```

Then open **http://localhost:8501** in your Windows browser.

---

## Extending the framework

Add a new search module in four steps:

1. Create `osint_framework/modules/my_engine.py` with a class exposing
   `name`, `engine`, `build_queries(target, target_type)` and
   `run(target, *, target_type, progress)` returning
   `{"results": [...], "attempted": [...]}`.
2. Route every row through `models.is_valid_hit` / `filter_valid_hits` — no
   exceptions, or you reintroduce false positives.
3. Export the class from `osint_framework/modules/__init__.py`.
4. Register it in `MODULE_MAP` in `osint_framework/main.py` and add a branch in
   `run_investigation`.

Then add a check to `scripts/smoke_test.py` and make sure
`python scripts/smoke_test.py` still passes before opening a pull request.

---

## Getting help

- **Something failed?** Run `python scripts/smoke_test.py` first — it tells you
  whether the problem is the install or your inputs/key.
- **Check the Live Log tab** in the dashboard, or re-run the CLI with `-v`.
- **The Queries tab** records every query and its error, including the ones that
  returned nothing.
- **Open an issue** with: your OS, `python --version`, the command you ran, the
  smoke-test output, and the `WARNING` / error text verbatim.

---

## Disclaimer

This framework only queries **public** indexes via SerpApi. It is intended for
legitimate security research, fraud investigation, and defensive OSINT. Always
corroborate findings before operational, legal, or HR action. Respect applicable
laws and SerpApi's terms of service.
