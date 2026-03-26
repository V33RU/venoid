"""Rules for detecting insecure data storage, logging, and dynamic code loading."""

from typing import List

from .base_rule import BaseRule, Finding, Severity, Confidence, dalvik_to_java


class InsecureLoggingRule(BaseRule):
    """Detect logging of sensitive data (credentials, tokens, PII) - CWE-532."""

    rule_id = "EXP-033"
    title = "Insecure Logging of Sensitive Data"
    severity = Severity.MEDIUM
    cwe = "CWE-532"
    component_type = "storage"
    description = (
        "Application logs sensitive information (passwords, tokens, keys, PII) "
        "via android.util.Log. Log output is readable by any app with READ_LOGS "
        "permission and visible in adb logcat without root on debug builds."
    )
    remediation = (
        "Remove all Log.d/v/i calls that include sensitive data. "
        "Use ProGuard/R8 rules to strip logging in release builds. "
        "Never log credentials, tokens, or user PII."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/532.html",
        "https://owasp.org/www-project-mobile-top-10/2016-risks/m2-insecure-data-storage",
    )

    # Keywords that indicate a log call may contain sensitive data.
    # These are matched against the calling method's class/method name as a heuristic.
    _SENSITIVE_KEYWORDS = (
        "password", "passwd", "token", "secret", "key", "auth",
        "credential", "session", "otp", "pin", "ssn", "credit",
        "card", "cvv", "account", "login", "user",
    )

    def check(self) -> List[Finding]:
        findings = []

        if not self.callgraph:
            return findings

        # search_methods returns callers of Log methods
        log_patterns = ["Landroid/util/Log;->d", "Landroid/util/Log;->v",
                        "Landroid/util/Log;->i", "Landroid/util/Log;->e",
                        "Landroid/util/Log;->w"]

        seen: set = set()
        for pattern in log_patterns:
            for method_sig in self.callgraph.search_methods(pattern):
                if method_sig in seen:
                    continue
                seen.add(method_sig)

                sig_lower = method_sig.lower()
                matched = next(
                    (kw for kw in self._SENSITIVE_KEYWORDS if kw in sig_lower), None
                )
                if not matched:
                    continue

                findings.append(self.create_finding(
                    component_name=dalvik_to_java(method_sig),
                    confidence=Confidence.POSSIBLE,
                    code_snippet=f"// Suspected sensitive log in: {method_sig}",
                    exploit_commands=[
                        "adb logcat | grep -i 'password\\|token\\|secret\\|auth'",
                        f"adb logcat | grep '{method_sig.split('->')[-1].split('(')[0]}'",
                    ],
                    exploit_scenario=(
                        f"Method containing keyword '{matched}' writes to logcat. "
                        "An attacker with adb access or READ_LOGS permission can capture "
                        "the sensitive value at runtime."
                    ),
                    api_level_affected="All (pre-API 19 any app can read logs)",
                ))

        return findings


class DynamicCodeLoadingRule(BaseRule):
    """Detect insecure dynamic code loading - CWE-829."""

    rule_id = "EXP-034"
    title = "Insecure Dynamic Code Loading"
    severity = Severity.HIGH
    cwe = "CWE-829"
    component_type = "code"
    description = (
        "Application loads DEX/JAR code at runtime using DexClassLoader or "
        "PathClassLoader from an uncontrolled location (external storage, network). "
        "An attacker with write access to that location can achieve RCE."
    )
    remediation = (
        "Load code only from the app's internal storage (getFilesDir/getCacheDir). "
        "Verify the integrity of loaded DEX files with a cryptographic signature "
        "before executing. Never load from external storage or HTTP URLs."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/829.html",
        "https://developer.android.com/training/articles/security-tips#DynamicCode",
    )

    _LOADER_PATTERNS = (
        "DexClassLoader",
        "PathClassLoader",
        "InMemoryDexClassLoader",
        "BaseDexClassLoader",
    )

    def check(self) -> List[Finding]:
        findings = []

        if not self.callgraph:
            return findings

        seen: set = set()
        for pattern in self._LOADER_PATTERNS:
            for method_sig in self.callgraph.search_methods(pattern):
                if method_sig in seen:
                    continue
                seen.add(method_sig)

                # Check callees for external-storage or network reads alongside the loader
                callees = self.callgraph.get_callees(method_sig)
                external = any(
                    kw in callee for callee in callees
                    for kw in ("getExternalStorage", "getExternalFilesDir",
                               "openConnection", "HttpURLConnection", "OkHttp")
                )
                confidence = Confidence.CONFIRMED if external else Confidence.LIKELY

                class_name = dalvik_to_java(method_sig)
                findings.append(self.create_finding(
                    component_name=class_name or "Application",
                    confidence=confidence,
                    code_snippet=(
                        f"new {pattern}(dexPath, optimizedDir, libPath, parent);\n"
                        "// Verify dexPath is NOT on external storage or from network"
                    ),
                    exploit_commands=[
                        "# Man-in-the-Disk: replace the DEX before it is loaded",
                        "adb shell 'echo malicious > /sdcard/payload.dex'",
                        "# Or intercept the download with mitmproxy and serve a patched DEX",
                    ],
                    exploit_scenario=(
                        f"App uses {pattern} to load code. If the source path is on "
                        "external storage or an HTTP URL, an attacker can replace the "
                        "DEX file and achieve remote code execution."
                    ),
                    api_level_affected="All",
                ))

        return findings


class SecureScreenFlagRule(BaseRule):
    """Detect activities missing FLAG_SECURE (application backgrounding / screenshot) - CWE-200."""

    rule_id = "EXP-035"
    title = "Missing FLAG_SECURE — Screen Capture / Backgrounding Risk"
    severity = Severity.LOW
    cwe = "CWE-200"
    component_type = "activity"
    description = (
        "Sensitive activities do not set WindowManager.LayoutParams.FLAG_SECURE, "
        "allowing the system or malicious apps to capture screenshots of the screen "
        "content and exposing it in the recent-apps thumbnail."
    )
    remediation = (
        "Call getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, "
        "WindowManager.LayoutParams.FLAG_SECURE) in onCreate() of all activities "
        "that display sensitive data (login, payment, profile)."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/200.html",
        "https://developer.android.com/reference/android/view/WindowManager.LayoutParams#FLAG_SECURE",
    )

    _SENSITIVE_ACTIVITY_KEYWORDS = (
        "login", "signin", "signup", "password", "payment", "checkout",
        "profile", "account", "wallet", "otp", "pin", "credit", "card",
    )

    def check(self) -> List[Finding]:
        findings = []

        if not self.callgraph:
            return findings

        # Find methods that call FLAG_SECURE / setFlags with secure flag
        secure_callers = set(self.callgraph.search_methods("FLAG_SECURE"))

        activities = self.apk_parser.get_activities()
        for activity in activities:
            name = activity["name"]
            name_lower = name.lower()

            # Only flag activities whose name suggests sensitive content
            is_sensitive = any(kw in name_lower for kw in self._SENSITIVE_ACTIVITY_KEYWORDS)
            if not is_sensitive:
                continue

            # Check if any method in this class calls FLAG_SECURE
            dalvik_prefix = "L" + name.replace(".", "/") + ";"
            uses_secure = any(dalvik_prefix in s for s in secure_callers)
            if uses_secure:
                continue

            findings.append(self.create_finding(
                component_name=name,
                confidence=Confidence.POSSIBLE,
                code_snippet=(
                    "// Add to onCreate():\n"
                    "getWindow().setFlags(\n"
                    "    WindowManager.LayoutParams.FLAG_SECURE,\n"
                    "    WindowManager.LayoutParams.FLAG_SECURE\n"
                    ");"
                ),
                exploit_commands=[
                    "# Capture recent-apps thumbnail (no special permission needed)",
                    "adb shell screencap -p /sdcard/screenshot.png && adb pull /sdcard/screenshot.png",
                    "# Or trigger from a malicious app via MediaProjection API",
                ],
                exploit_scenario=(
                    f"{name} displays sensitive data but does not set FLAG_SECURE. "
                    "The OS saves a thumbnail visible in the recent-apps screen, and a "
                    "background app can capture it via MediaProjection without user consent."
                ),
                api_level_affected="All",
            ))

        return findings
