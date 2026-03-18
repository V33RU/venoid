"""Rules for detecting application-level manifest and configuration vulnerabilities."""

from typing import List

from .base_rule import BaseRule, Finding, Severity, Confidence
from core.apk_parser import ANDROID_NS


class InsecureNetworkConfigRule(BaseRule):
    """Detect insecure network security configurations."""

    rule_id = "EXP-017"
    title = "Insecure Network Security Configuration"
    severity = Severity.HIGH
    cwe = "CWE-295"
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
    description = "Application has debug mode enabled, exposing sensitive information."

    def check(self) -> List[Finding]:
        """Check for debug flags."""
        findings = []

        app_elem = self._get_manifest_app_element()
        if app_elem is not None:
            debuggable = app_elem.get(f"{{{ANDROID_NS}}}debuggable")
            if debuggable == "true":
                findings.append(self.create_finding(
                    component_name="Application",
                    confidence=Confidence.CONFIRMED,
                    details={"issue": "Debug mode enabled in manifest"},
                    code_snippet='android:debuggable="true"',
                    remediation="Set android:debuggable to false for release builds.",
                    exploit_commands=[
                        "# Attach debugger",
                        "adb shell am set-debug-app -w --persistent com.package.name",
                        "adb shell am start -D -n com.package.name/.MainActivity"
                    ]
                ))

        debug_methods = self.callgraph.search_methods("Log.d") if self.callgraph else []
        if debug_methods:
            findings.append(self.create_finding(
                component_name="Application",
                confidence=Confidence.LIKELY,
                details={"issue": "Debug logging found in code", "method_count": len(debug_methods)},
                code_snippet="Debug logging methods detected",
                remediation="Remove debug logs and use ProGuard to strip them in release builds.",
                exploit_commands=["# Check log output", "adb logcat | grep $(adb shell pidof com.package.name)"]
            ))

        return findings


class BackupEnabledRule(BaseRule):
    """Detect backup enabled exposing app data."""

    rule_id = "EXP-019"
    title = "Backup Enabled - Data Exposure Risk"
    severity = Severity.MEDIUM
    cwe = "CWE-530"
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
            confidence = None  # explicitly "false" — safe

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
    description = "PendingIntent created without FLAG_IMMUTABLE, allowing malicious apps to modify intent."

    def check(self) -> List[Finding]:
        """Check for PendingIntent usage."""
        findings = []

        if not self.callgraph:
            return findings

        pending_intent_methods = self.callgraph.search_methods("PendingIntent;->get")
        target_sdk = self._safe_sdk_int(self.apk_parser.get_target_sdk())

        for method in pending_intent_methods:
            findings.append(self.create_finding(
                component_name=method.split("->")[0] if "->" in method else "Application",
                confidence=Confidence.POSSIBLE,
                details={
                    "issue": "PendingIntent may be missing FLAG_IMMUTABLE",
                    "method": method,
                    "target_sdk": target_sdk
                },
                code_snippet="PendingIntent.getActivity(context, 0, intent, 0)  // Verify FLAG_IMMUTABLE is set",
                remediation="Add PendingIntent.FLAG_IMMUTABLE (API 23+) or FLAG_MUTABLE explicitly. Required on API 31+.",
                exploit_commands=["# Verify FLAG_IMMUTABLE is set in the PendingIntent creation call"]
            ))

        return findings
