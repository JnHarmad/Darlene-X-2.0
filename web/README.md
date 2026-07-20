# Darlene-X_2.0 (offline / serverless)

Static Android APK malware analysis that runs **entirely in your browser**.
APK samples, analysis state, and reports never leave the machine.

**Product:** Darlene-X_2.0 · **Version:** 2.0.0

## Quick start (local only)

```bash
cd web
python -m http.server 8080
```

Open `http://127.0.0.1:8080` — do **not** open `index.html` via `file://` (WASM fetch needs HTTP).

## Privacy model

| Surface | Behavior |
|--------|----------|
| Sample APK | Parsed in-memory with JSZip; never uploaded |
| Report JSON/CSV | Downloaded locally via Blob URLs |
| Network | CSP `connect-src 'self'` for assets; optional VT/AI only when you set keys |
| Core verdict | Always local and deterministic |

## Layout

```
web/
  index.html
  vendor/jszip.min.js
  js/engine/
    detection-rules.js
    wasm-bridge.js
  wasm/
    hotpath.wat
    hotpath.wasm
```

## Rebuild WASM (optional)

```bash
cd web/wasm
npm install --no-save wabt@1.0.36
node -e "require('wabt')().then(w=>{const fs=require('fs');const m=w.parseWat('hotpath.wat',fs.readFileSync('hotpath.wat','utf8'));m.validate();fs.writeFileSync('hotpath.wasm',Buffer.from(m.toBinary({}).buffer));})"
```
