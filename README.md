# Venoid

Android APK static security analyzer. Detects exported component vulnerabilities, tracks taint flows from sources to sinks, and outputs a structured JSON report.

## Install

```bash
git clone https://github.com/V33RU/Venoid.git
cd Venoid
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# Scan and save JSON + HTML reports (default)
python3 cli.py scan app.apk

# Show all severity levels
python3 cli.py scan app.apk --all

# Filter by component type and severity
python3 cli.py scan app.apk -t activities,deeplinks -s CRITICAL,HIGH

# Print findings table in terminal
python3 cli.py scan app.apk --show-findings

# Save report to custom directory
python3 cli.py scan app.apk -d ./reports

# List all available rules
python3 cli.py rules
```

## Detection Rules (21)

| ID | Title | Severity |
|----|-------|----------|
| **Activities** | | |
| EXP-001 | Exported Activity Without Permission | HIGH |
| EXP-002 | Intent Data to WebView Load | CRITICAL |
| EXP-023 | Insecure WebView JavaScript Bridge | HIGH |
| EXP-036 | WebView Universal File Access Enabled | CRITICAL |
| **Services** | | |
| EXP-004 | Exported Service Without Permission | HIGH |
| **Receivers** | | |
| EXP-006 | Exported Broadcast Receiver Without Permission | HIGH |
| EXP-007 | Dynamic Receiver Without Export Flag | MEDIUM |
| EXP-039 | Unprotected Outgoing Broadcast | MEDIUM |
| **Providers** | | |
| EXP-009 | Exported Content Provider Without Permission | HIGH |
| EXP-012 | Global URI Permission Grant | HIGH |
| **Deep Links** | | |
| EXP-013 | Missing Deep Link autoVerify | MEDIUM |
| **Manifest / Config** | | |
| EXP-017 | Insecure Network Security Config | MEDIUM |
| EXP-018 | Debug Mode Enabled (android:debuggable) | HIGH |
| EXP-019 | Backup Enabled (android:allowBackup) | MEDIUM |
| **Crypto** | | |
| EXP-016 | Hardcoded Cryptographic Key | CRITICAL |
| EXP-024 | Insecure Random Number Generator | MEDIUM |
| **Storage** | | |
| EXP-033 | Insecure Logging of Sensitive Data | MEDIUM |
| EXP-035 | Missing FLAG_SECURE (Screen Capture Risk) | LOW |
| **Network** | | |
| EXP-049 | API Key / Secret Leakage | HIGH |
| EXP-050 | Cleartext Traffic Pattern Detected | MEDIUM |
| **Security** | | |
| EXP-044 | File-Based Root Detection (awareness) | INFO |

## How It Works

1. **APK parsing** — unpacks manifest, resources, and DEX bytecode via androguard
2. **Call graph** — builds a method-level call graph across all DEX files
3. **Taint engine** — traces data flow from user-controlled sources (`getIntent`, `getStringExtra`, `getQueryParameter`) to dangerous sinks (`loadUrl`, `rawQuery`, `exec`, `startActivity`)
4. **Rules** — each rule queries the call graph, manifest, or taint paths and emits structured findings with CWE, severity, and remediation advice

## Output

JSON report saved as `venoid_report_<package>.json`:

```json
{
  "package": "com.example.app",
  "total_findings": 5,
  "findings": [
    {
      "rule_id": "EXP-001",
      "title": "Exported Activity Without Permission",
      "severity": "HIGH",
      "confidence": "CONFIRMED",
      "component": "com.example.MainActivity",
      "cwe": "CWE-926",
      "description": "...",
      "exploit_commands": ["adb shell am start -n com.example/.MainActivity"]
    }
  ]
}
```

Exits with code `1` when CRITICAL findings are present (CI-friendly).

## Project Structure

```
core/         APK parsing, call graph, taint engine
rules/        20 detection rules across 9 modules
exploit/      ADB command hint generation
tests/        Unit tests (65 passing)
cli.py        Entry point
```

## Venoid Pro

Venoid Pro is a web-based version with 32 additional rules and advanced features:

- **52 total rules** — includes taint-based, SSL bypass, advanced root detection bypass, native code, obfuscation, and permission over-privilege analysis
- **Frida script generation** — auto-generates runnable `.js` hooks per finding
- **Full exploit hints** — intent fuzzing, drozer commands, manual steps, payloads
- **Attack scenarios** — attacker profile, impact analysis, CVE references
- **Web UI** — upload APK, real-time scan progress, report dashboard, scan history

## License

MIT
