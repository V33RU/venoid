"""Rules for detecting exported Broadcast Receiver vulnerabilities."""

from typing import List

from .base_rule import BaseRule, Finding, Severity, Confidence


class ExportedReceiverRule(BaseRule):
    """Detect exported broadcast receivers without proper permissions."""

    rule_id = "EXP-006"
    title = "Exported Broadcast Receiver Without Permission"
    severity = Severity.HIGH
    cwe = "CWE-925"
    description = "Broadcast receiver is exported without requiring a permission, allowing any app to send broadcasts to it."
    remediation = "Set android:exported=\"false\" or define a signature-level permission."
    references = [
        "https://cwe.mitre.org/data/definitions/925.html",
        "https://developer.android.com/guide/components/broadcasts#security"
    ]

    def check(self) -> List[Finding]:
        """Check for exported receivers without permissions."""
        findings = []
        receivers = self.apk_parser.get_receivers()

        for receiver in receivers:
            if not receiver['exported']:
                continue

            # Skip known third-party SDK receivers — they are legitimately exported
            if self._is_third_party_component(receiver['name']):
                continue

            # Check if protected by signature-level permission
            if self._is_protected(receiver.get('permission')):
                continue

            exploit_cmds = [
                f"adb shell am broadcast -n {self.apk_parser.get_package_name()}/{receiver['name']}",
                f"adb shell am broadcast -a android.intent.action.BOOT_COMPLETED -n {self.apk_parser.get_package_name()}/{receiver['name']}"
            ]

            finding = self.create_finding(
                component_name=receiver['name'],
                confidence=Confidence.LIKELY,
                exploit_commands=exploit_cmds,
                exploit_scenario=f"Any malicious app can send broadcasts to {receiver['name']} without restrictions.",
                api_level_affected="All"
            )
            findings.append(finding)

        return findings


class DynamicReceiverRule(BaseRule):
    """Detect dynamically registered receivers without RECEIVER_EXPORTED flag (API 33+)."""

    rule_id = "EXP-007"
    title = "Dynamic Receiver Missing Export Flag"
    severity = Severity.MEDIUM
    cwe = "CWE-925"
    description = "Dynamically registered receiver may be exported on API 33+ without RECEIVER_NOT_EXPORTED flag."
    remediation = "Use Context.RECEIVER_NOT_EXPORTED flag when registering receivers on API 33+."
    references = [
        "https://developer.android.com/about/versions/13/behavior-changes-13#runtime-received-broadcasts"
    ]

    def check(self) -> List[Finding]:
        """Check for dynamic receiver registration issues."""
        findings = []
        target_sdk = self.apk_parser.get_target_sdk()

        # Ensure target_sdk is an integer
        try:
            target_sdk = int(target_sdk) if target_sdk else 0
        except (ValueError, TypeError):
            target_sdk = 0

        # Only relevant for API 33+
        if target_sdk < 33:
            return findings

        # Search for registerReceiver calls without export flags
        if self.callgraph:
            methods = self.callgraph.search_methods("registerReceiver")
            for method in methods:
                # Check if flag is present - simplified check
                if "RECEIVER_NOT_EXPORTED" not in method:
                    finding = self.create_finding(
                        component_name=method,
                        confidence=Confidence.POSSIBLE,
                        exploit_commands=[
                            f"adb shell am broadcast -a android.intent.action.BOOT_COMPLETED --receiver-include-background"
                        ],
                        exploit_scenario="Dynamically registered receiver may be accessible to other apps on API 33+.",
                        api_level_affected="API 33+"
                    )
                    findings.append(finding)

        return findings


class ReceiverInjectionRule(BaseRule):
    """Detect receivers that process intent data without validation."""

    rule_id = "EXP-008"
    title = "Broadcast Receiver Intent Injection"
    severity = Severity.HIGH
    cwe = "CWE-20"
    description = "Exported receiver passes user-controlled broadcast data to a dangerous sink without validation."
    remediation = "Validate all intent extras in onReceive() before processing."
    references = [
        "https://cwe.mitre.org/data/definitions/20.html",
        "https://developer.android.com/guide/components/broadcasts#security"
    ]

    def check(self) -> List[Finding]:
        """Check for taint flow in exported receivers."""
        findings = []

        if not self.taint_engine:
            return findings

        receivers = self.apk_parser.get_receivers()

        for receiver in receivers:
            if not receiver['exported']:
                continue

            # Check for taint paths from this receiver's class to dangerous sinks
            dangerous_sinks = ["exec(", "rawQuery", "execSQL", "loadUrl", "openFile", "startActivity"]
            for sink_pattern in dangerous_sinks:
                for path in self.taint_engine.get_paths_to_sink(sink_pattern):
                    if receiver['name'] in path.source or receiver['name'] in path.sink:
                        exploit_cmds = [
                            f"adb shell am broadcast -n {self.apk_parser.get_package_name()}/{receiver['name']} "
                            f"--es cmd 'injected_data'",
                        ]

                        finding = self.create_finding(
                            component_name=receiver['name'],
                            confidence=Confidence.CONFIRMED,
                            taint_path=[{"method": step.method, "instruction": step.instruction} for step in path.steps],
                            exploit_commands=exploit_cmds,
                            exploit_scenario=f"Attacker can inject malicious data through broadcast intents reaching {sink_pattern}.",
                            api_level_affected="All"
                        )
                        findings.append(finding)

        return findings
