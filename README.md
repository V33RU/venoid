# ExPoser

Android APK static security analyzer. Detects exported component vulnerabilities, tracks taint flows, and generates exploit hints.

## Install

```bash
git clone https://github.com/yourorg/exposer.git
cd exposer
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan (HTML report)
python3 cli.py scan app.apk

# Multiple formats + exploit hints
python3 cli.py scan app.apk -o html -o json -e

# Filter components and severity
python3 cli.py scan app.apk -t activities,deeplinks -s CRITICAL,HIGH

# Save to custom directory
python3 cli.py scan app.apk -d ./reports

# Full help
python3 cli.py scan --help
```

## What it detects

| Area | Rules |
|------|-------|
| Activities | Exported without permission, WebView intent load, StrandHogg, Tapjacking |
| Services | Exported without permission, intent injection |
| Receivers | Exported/dynamic without permission, injection |
| Providers | Exported without permission, SQL injection, path traversal, URI grants |
| Deep Links | Missing autoVerify, open redirect, custom scheme hijacking |
| Manifest | Debug mode, backup enabled, insecure network config, mutable PendingIntent |
| Crypto | Hardcoded keys, insecure RNG |

## Reports

- `html` — interactive, browser-readable
- `json` — machine-readable, includes exploit hints
- `sarif` — SARIF 2.1.0 for GitHub code scanning upload

Exits with code `1` when CRITICAL findings are present (CI-friendly).

## Structure

```
core/        APK parsing, call graph, taint engine
rules/       24 detection rules across 7 modules
exploit/     ADB / Frida / drozer hint generation
report/      HTML, JSON, SARIF report writers
cli.py       Entry point
```

//hello123

## License

MIT
