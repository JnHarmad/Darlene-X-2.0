# Darlene-X_2.0

Offline static Android APK malware analysis — **CLI** and **browser** engines.

**Product:** Darlene-X_2.0 · **Version:** 2.0.0 · **CLI:** `darlene-x-2`

## Web (local only)

```bash
cd web
python -m http.server 8080
# open http://127.0.0.1:8080
```

## CLI

```bash
pip install -e .
darlene-x-2 analyze path/to/app.apk -o ./out
```

Python imports remain `darlene_x` (package path). Distribution name is `darlene-x-2`.
