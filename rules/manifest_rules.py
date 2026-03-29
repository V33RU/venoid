"""Rules for detecting application-level manifest and configuration vulnerabilities."""

from typing import List

from .base_rule import BaseRule, Finding, Severity, Confidence, dalvik_to_java
from core.apk_parser import ANDROID_NS


class InsecureNetworkConfigRule(BaseRule):
    """Detect insecure network security configurations."""

    rule_id = "EXP-017"
    title = "Insecure Network Security Configuration"
    severity = Severity.HIGH
    cwe = "CWE-295"
    component_type = "manifest"
    description = "App allows cleartext traffic or accepts all certificates."

    def check(self) -> List[Finding]:
        """Check network security config."""
        findings = []

        app_elem = self._get_manifest_app_element()
        if app_elem is None:
            return findings

        cleartext = app_elem.get(f"{{{ANDROID_NS}}}usesCleartextTraffic")
        if cleartext == "true":
            findings.append(self.create_finding(
                component_name="Application",
                confidence=Confidence.CONFIRMED,
                details={"issue": "Cleartext traffic enabled"},
                code_snippet='android:usesCleartextTraffic="true"',
                remediation="Set usesCleartextTraffic to false and use HTTPS only.",
                exploit_commands=["# Intercept traffic", "mitmproxy --mode transparent"]
            ))

        config_file = app_elem.get(f"{{{ANDROID_NS}}}networkSecurityConfig")
        if config_file:
            findings.append(self.create_finding(
                component_name="Application",
                confidence=Confidence.POSSIBLE,
                details={"issue": "Custom network security config", "config": config_file},
                code_snippet=f'android:networkSecurityConfig="@{config_file}"',
                remediation="Review network_security_config.xml for insecure settings.",
                exploit_commands=["# Check config file", "apktool d base.apk && cat res/xml/network_security_config.xml"]
            ))

        return findings


class DebugModeEnabledRule(BaseRule):
    """Detect debug mode enabled in release builds."""

    rule_id = "EXP-018"
    title = "Debug Mode Enabled"
    severity = Severity.HIGH
    cwe = "CWE-489"
    component_type = "manifest"
    description = "Application has android:debuggable=\"true\" in the manifest, allowing debugger attachment and bypassing security controls."

    def check(self) -> List[Finding]:
        """Check for debuggable flag in manifest.

        Note: Only checks android:debuggable in the manifest. Log.d presence
        is NOT flagged - it appears in virtually every app (including SDK code)
        and produces near-100% false positive rates with no actionable signal.
        """
        findings = []

        app_elem = self._get_manifest_app_element()
        if app_elem is None:
            return findings

        debuggable = app_elem.get(f"{{{ANDROID_NS}}}debuggable")
        if debuggable == "true":
            pkg = self.apk_parser.get_package_name()
            findings.append(self.create_finding(
                component_name="Application",
                confidence=Confidence.CONFIRMED,
                details={"issue": "android:debuggable=\"true\" set in manifest"},
                code_snippet='android:debuggable="true"',
                remediation="Remove android:debuggable or set it to false. Ensure release builds are signed with a release key.",
                exploit_commands=[
                    "# Attach JDWP debugger",
                    f"adb shell am set-debug-app -w --persistent {pkg}",
                    f"adb shell am start -D -n {pkg}/.MainActivity",
                    "# Or extract app data without root via backup",
                    f"adb backup -apk -shared {pkg}",
                ]
            ))

        return findings


class BackupEnabledRule(BaseRule):
    """Detect backup enabled exposing app data."""

    rule_id = "EXP-019"
    title = "Backup Enabled - Data Exposure Risk"
    severity = Severity.MEDIUM
    cwe = "CWE-530"
    component_type = "manifest"
    description = "Application data can be backed up and restored, potentially exposing sensitive information."

    def check(self) -> List[Finding]:
        """Check for backup settings."""
        findings = []

        app_elem = self._get_manifest_app_element()
        if app_elem is None:
            return findings

        allow_backup = app_elem.get(f"{{{ANDROID_NS}}}allowBackup")

        if allow_backup == "true":
            confidence = Confidence.CONFIRMED
        elif allow_backup is None:
            confidence = Confidence.POSSIBLE
        else:
            confidence = None  # explicitly "false" - safe

        if confidence is not None:
            findings.append(self.create_finding(
                component_name="Application",
                confidence=confidence,
                details={
                    "issue": "Backup enabled (default or explicit)",
                    "allowBackup": allow_backup or "not set (defaults to true)"
                },
                code_snippet=f'android:allowBackup="{allow_backup or "true (default)"}"',
                remediation="Set android:allowBackup to false to prevent data backup.",
                exploit_commands=[
                    "adb backup -apk -shared com.package.name",
                    "dd if=backup.ab bs=1 skip=24 | zlib-flate -uncompress | tar -xvf -"
                ]
            ))

        return findings


class PendingIntentVulnerabilityRule(BaseRule):
    """Detect mutable PendingIntent vulnerabilities."""

    rule_id = "EXP-022"
    title = "Mutable PendingIntent Vulnerability"
    severity = Severity.HIGH
    cwe = "CWE-927"
    component_type = "intent"
    description = "PendingIntent created without FLAG_IMMUTABLE, allowing malicious apps to modify the wrapped intent."

    def check(self) -> List[Finding]:
        """Check for PendingIntent usage without FLAG_IMMUTABLE.

        Strategy: for each method that calls PendingIntent.get*, check whether
        FLAG_IMMUTABLE or FLAG_MUTABLE appears anywhere in the same method's
        callees.  FLAG_IMMUTABLE = 0x04000000 - it shows up as a field reference
        to android.app.PendingIntent.FLAG_IMMUTABLE in the bytecode.  If neither
        flag is found, the PendingIntent is likely mutable (required to be explicit
        on API 31+).
        """
        findings = []

        if not self.callgraph:
            return findings

        target_sdk = self._safe_sdk_int(self.apk_parser.get_target_sdk())
        # On API 31+ FLAG_IMMUTABLE is mandatory - raise severity to HIGH, else MEDIUM
        base_confidence = Confidence.LIKELY if target_sdk >= 31 else Confidence.POSSIBLE

        callers = self.callgraph.search_methods("PendingIntent;->get")
        seen: set = set()

        for caller_sig in callers:
            if caller_sig in seen:
                continue
            seen.add(caller_sig)

            callees = self.callgraph.get_callees(caller_sig)
            context_strings = [caller_sig] + list(callees)

            # If FLAG_IMMUTABLE or FLAG_MUTABLE is explicitly referenced, skip
            has_immutable = any(
                "FLAG_IMMUTABLE" in s or "FLAG_MUTABLE" in s
                for s in context_strings
            )
            if has_immutable:
                continue

            class_name = dalvik_to_java(caller_sig)

            findings.append(self.create_finding(
                component_name=class_name,
                confidence=base_confidence,
                details={
                    "issue": "PendingIntent created without FLAG_IMMUTABLE",
                    "caller": caller_sig,
                    "target_sdk": target_sdk
                },
                code_snippet=(
                    "// Vulnerable:\n"
                    "PendingIntent.getActivity(context, 0, intent, 0);\n"
                    "// Fixed:\n"
                    "PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG_IMMUTABLE);"
                ),
                remediation=(
                    "Pass PendingIntent.FLAG_IMMUTABLE as the flags argument (API 23+). "
                    "Required on API 31+. Use FLAG_MUTABLE only if the intent must be modified by the system."
                ),
                exploit_commands=[
                    "# A malicious app can intercept and modify the mutable PendingIntent",
                    "# to redirect it to an arbitrary component or add extra data.",
                    "# Manual verification required: check the flags argument in the source.",
                ],
                api_level_affected="All (mandatory on API 31+)"
            ))

        return findings
