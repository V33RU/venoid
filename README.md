# ExPoser

Android APK static security analyzer. Detects exported component vulnerabilities, tracks taint flows from sources to sinks, and generates ready-to-run exploit hints.

## Install

```bash
git clone https://github.com/yourorg/exposer.git
cd exposer
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan - produces an HTML report
python3 cli.py scan app.apk

# Multiple output formats with exploit hints
python3 cli.py scan app.apk -o html -o json -o sarif -e

# Filter by component type and severity
python3 cli.py scan app.apk -t activities,deeplinks -s CRITICAL,HIGH

# Save reports to a custom directory
python3 cli.py scan app.apk -d ./reports

# List all available rules
python3 cli.py rules

# Full help
python3 cli.py scan --help
```

## Detection Rules (38)

| ID | Title | Severity |
|----|-------|----------|
| **Activities** | | |
| EXP-001 | Exported Activity Without Permission | HIGH |
| EXP-002 | Intent Data to WebView Load | HIGH |
| EXP-003 | Nested Intent Forwarding (StrandHogg 2.0) | HIGH |
| EXP-020 | Task Hijacking Vulnerability (StrandHogg) | MEDIUM |
| EXP-021 | Tapjacking Vulnerability | MEDIUM |
| EXP-023 | Insecure WebView JavaScript Bridge | HIGH |
| EXP-030 | Fragment Injection via PreferenceActivity | HIGH |
| EXP-031 | Arbitrary File Read via WebResourceResponse | HIGH |
| EXP-036 | WebView Universal File Access Enabled | CRITICAL |
| EXP-037 | Intent Redirection (Privilege Escalation) | HIGH |
| **Services** | | |
| EXP-004 | Exported Service Without Permission | HIGH |
| EXP-005 | Service Intent Injection | HIGH |
| **Receivers** | | |
| EXP-006 | Exported Broadcast Receiver Without Permission | HIGH |
| EXP-007 | Dynamic Receiver Without Export Flag | MEDIUM |
| EXP-008 | Broadcast Receiver Intent Injection | HIGH |
| EXP-039 | Unprotected Outgoing Broadcast | MEDIUM |
| EXP-040 | Sticky Broadcast Usage | MEDIUM |
| **Providers** | | |
| EXP-009 | Exported Content Provider Without Permission | HIGH |
| EXP-010 | Content Provider SQL Injection | CRITICAL |
| EXP-011 | Content Provider Path Traversal | HIGH |
| EXP-012 | Global URI Permission Grant | MEDIUM |
| EXP-032 | Typo Permission (Undeclared Protection) | HIGH |
| EXP-038 | FileProvider Exposes Broad File Paths | MEDIUM |
| **Deep Links** | | |
| EXP-013 | Missing Deep Link autoVerify | MEDIUM |
| EXP-014 | Deep Link Open Redirect | HIGH |
| EXP-015 | Custom Scheme Hijacking | MEDIUM |
| **Manifest / Config** | | |
| EXP-017 | Insecure Network Security Config | MEDIUM |
| EXP-018 | Debug Mode Enabled (android:debuggable) | HIGH |
| EXP-019 | Backup Enabled (android:allowBackup) | MEDIUM |
| EXP-022 | Mutable PendingIntent Without FLAG_IMMUTABLE | HIGH |
| **Crypto / TLS** | | |
| EXP-016 | Hardcoded Cryptographic Key | CRITICAL |
| EXP-024 | Insecure Random Number Generator | MEDIUM |
| EXP-041 | Broken TrustManager (Accepts All Certificates) | CRITICAL |
| EXP-042 | Allow-All HostnameVerifier (Hostname Verification Disabled) | HIGH |
| EXP-043 | WebView SSL Error Silently Ignored | HIGH |
| **Storage / Code** | | |
| EXP-033 | Insecure Logging of Sensitive Data | MEDIUM |
| EXP-034 | Insecure Dynamic Code Loading | HIGH |
| EXP-035 | Missing FLAG_SECURE (Screen Capture Risk) | LOW |

## Reports

| Format | Description |
|--------|-------------|
| `html` | Dark interactive report - findings grouped by vulnerability type, per-component attack commands |
| `json` | Machine-readable, full finding detail including taint paths and Frida script |
| `sarif` | SARIF 2.1.0 for GitHub Advanced Security / code scanning upload |

Exits with code `1` when CRITICAL or HIGH findings are present (CI-friendly).

## Frida Scripts

Pass `-e` / `--exploit-hints` to auto-generate a runnable Frida JS script for every finding:

```bash
python3 cli.py scan app.apk -e
```

Scripts are written to `./frida/<RULE-ID>_<Component>.js` and printed at the end of the scan.
Each script hooks the exact vulnerable method for that finding - logging arguments, dumping key
material, confirming bypasses - and can be run directly:

```bash
frida -U -n com.example.app -s frida/EXP-002_MainActivity.js
```

Coverage: all 38 rules have dedicated templates (EXP-001 through EXP-043).

## How It Works

1. **APK parsing** - unpacks manifest, resources, and DEX bytecode via androguard
2. **Call graph** - builds a method-level call graph across all DEX files
3. **Taint engine** - traces data flow from user-controlled sources (`getIntent`, `getStringExtra`, `getQueryParameter`, …) to dangerous sinks (`loadUrl`, `rawQuery`, `exec`, `startActivity`, …)
4. **Rules** - each rule queries the call graph, manifest, or taint paths and emits structured findings with CWE, CVSS score, exploit commands, and remediation advice

## Project Structure

```
core/              APK parsing, call graph, taint engine
rules/             38 detection rules across 8 modules
exploit/           ADB / Frida / drozer hint generation
  frida_scripts.py   Per-rule Frida JS script templates (all 38 rules)
report/            HTML, JSON, SARIF report writers
cli.py             Entry point
FUTURE_ADDONS.md   Planned enhancements and ideas
```

## License

MIT
