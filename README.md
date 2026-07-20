# Darlene-X_2.0

Serverless static Android APK malware analysis — **CLI** and **browser** engines.

**Product:** Darlene-X_2.0 · **Version:** 2.0.0 · **CLI:** `darlene-x-2`

Core detection runs in your browser (or via CLI on your machine). The web product is **serverless**: static assets only, no analysis backend — so there is no server-side attack surface for man-in-the-middle (MiM) interception of your sample during the core scan. Once a public URL is published, you visit the site, drop an APK, and analyze in-browser.

Optional **VirusTotal** cross-vendor intel and preferred **AI-assisted report interpretation** will be available when you choose to enable them.

---

## Features

- **Serverless web analysis** — no analysis server in the middle; static hosting only, core verdict computed client-side
- **WebAssembly hot path** — packing / entropy heuristics via a local WASM module for a faster analysis loop, with a pure-JS fallback if WASM is unavailable
- **Robust Android malware detection** — multi-phase static checks covering unpacking, signatures, manifest / permissions, dangerous APIs, and secrets / endpoint patterns
- **User-friendly report dashboard** — severity stats, scan queue status, and downloadable reports (JSON / CSV from the web UI; JSON / HTML from the CLI)
- **Optional VirusTotal intel** — cross-vendor reputation lookup when you opt in with a key
- **Preferred AI-assisted report interpretation** — natural-language readout of findings when you enable an AI provider

---

## Architecture

```text
                    ┌─────────────────────────────────────┐
                    │           Darlene-X_2.0             │
                    └─────────────────┬───────────────────┘
                                      │
              ┌───────────────────────┴───────────────────────┐
              │                                               │
              ▼                                               ▼
    ┌─────────────────────┐                       ┌─────────────────────┐
    │   Web (serverless)  │                       │   CLI (Python)      │
    │   web/              │                       │   darlene_x/        │
    └─────────┬───────────┘                       └─────────┬───────────┘
              │                                               │
    JSZip → rules + WASM                              analysers (phases)
    → dashboard + report                              → orchestrator
    → optional VT / AI                                → SQLite + report
                                                      → optional VT / AI
```

### Web (`web/`)

| Path | Role |
|------|------|
| `index.html` | UI, scan flow, and report dashboard |
| `vendor/jszip.min.js` | In-memory APK unzip for core analysis |
| `js/engine/detection-rules.js` | Static Android malware / risk heuristics |
| `js/engine/wasm-bridge.js` | Loads `hotpath.wasm`; falls back to JS |
| `wasm/hotpath.wasm` | Fast packing / entropy path (rebuild from `.wat` if needed) |

Flow: open the hosted URL (or local preview) → drop APK → detection rules + WASM heuristics → dashboard → download report → optionally enrich with VirusTotal / AI.

### CLI (`darlene_x/`)

| Path | Role |
|------|------|
| `cli.py` | Entry point (`darlene-x-2 analyze` / `query`) |
| `core/base.py` | `Finding` + `BaseAnalyser` contract |
| `core/orchestrator.py` | Parallel / serial phase runner |
| `core/result_store.py` | SQLite-backed findings store |
| `core/tool_runner.py` | Safe external-tool execution helpers |
| `analysers/` | Phases: unpack, signature, manifest, code/APIs, secrets |

Flow: APK path → phased analysers → orchestrator → `results.db` + JSON/HTML report under `-o`.

### Out of scope for the product engines

| Path | Note |
|------|------|
| `frontend/` | Deprecated browser prototype — use `web/` |
| `Understanding_logical_flow/` | Reference / older server-style flow, not shipped as the 2.0 engine |
| `darlene_x.html` | Standalone HTML demo, not the modular `web/` app |

---

## Quick start

### Web

**Hosted:** a public URL will be shared when the site is live — open it in your browser and analyze there.

**Local preview** (while developing):

```bash
cd web
python -m http.server 8080
# open http://127.0.0.1:8080
```

Serve over HTTP(S) — do not open `index.html` via `file://` (WASM fetch needs a normal origin).

### CLI

```bash
pip install -e .
darlene-x-2 analyze path/to/app.apk -o ./out
```

Python imports remain `darlene_x` (package path). Distribution name is `darlene-x-2`.

---

## Trust model (web)

| Surface | Behavior |
|---------|----------|
| Core analysis | Serverless / client-side — no analysis backend to MiM your APK |
| Sample handling | Parsed in the browser for the core verdict |
| Report | Dashboard + local download (JSON / CSV) |
| VirusTotal | Optional cross-vendor intel when enabled |
| AI assist | Optional preferred interpretation of the report when enabled |

---

## Footnote

> Testing on malware samples is ongoing. The tool will be live soon. Until then, the malware detection logic is open to review — improvement ideas and contributions are most welcome.
