"""Rules for detecting exported Service vulnerabilities."""

from typing import List

from .base_rule import BaseRule, Finding, Severity, Confidence


class ExportedServiceRule(BaseRule):
    """Detect exported services without proper permissions."""

    rule_id = "EXP-004"
    title = "Exported Service Without Permission"
    severity = Severity.HIGH
    cwe = "CWE-926"
    description = "Service is exported without requiring a permission, allowing any app to bind or start it."
    remediation = "Set android:exported=\"false\" or define a signature-level permission."
    references = (
        "https://cwe.mitre.org/data/definitions/926.html",
        "https://developer.android.com/guide/components/services"
    )

    def check(self) -> List[Finding]:
        """Check for exported services without permissions."""
        findings = []
        services = self.apk_parser.get_services()

        for service in services:
            if not service['exported']:
                continue

            # Skip known third-party SDK services — they are legitimately exported
            if self._is_third_party_component(service['name']):
                continue

            # Check if protected by signature-level permission
            if self._is_protected(service.get('permission')):
                continue

            exploit_cmds = [
                f"adb shell am startservice -n {self.apk_parser.get_package_name()}/{service['name']}",
                f"adb shell am start-foreground-service -n {self.apk_parser.get_package_name()}/{service['name']}",
            ]

            finding = self.create_finding(
                component_name=service['name'],
                confidence=Confidence.LIKELY,
                exploit_commands=exploit_cmds,
                exploit_scenario=f"Any malicious app can start or bind to {service['name']} without restrictions.",
                api_level_affected="All"
            )
            findings.append(finding)

        return findings


class ServiceIntentInjectionRule(BaseRule):
    """Detect services that process intent data without validation."""

    rule_id = "EXP-005"
    title = "Service Intent Data Injection"
    severity = Severity.HIGH
    cwe = "CWE-20"
    description = "Exported service passes user-controlled intent data to a dangerous sink without validation."
    remediation = "Validate all intent extras before processing. Use explicit intents."
    references = (
        "https://cwe.mitre.org/data/definitions/20.html",
        "https://developer.android.com/guide/components/services"
    )

    def check(self) -> List[Finding]:
        """Check for taint flow in exported services."""
        findings = []

        if not self.taint_engine:
            return findings

        services = self.apk_parser.get_services()

        seen: set = set()
        for service in services:
            if not service['exported']:
                continue

            # Check for taint paths from this service's class to dangerous sinks
            dangerous_sinks = ["exec(", "rawQuery", "execSQL", "loadUrl", "openFile", "sendBroadcast"]
            for sink_pattern in dangerous_sinks:
                for path in self.taint_engine.get_paths_to_sink(sink_pattern):
                    if service['name'] in path.source or service['name'] in path.sink:
                        key = (service['name'], sink_pattern)
                        if key in seen:
                            continue
                        seen.add(key)

                        exploit_cmds = [
                            f"adb shell am startservice -n {self.apk_parser.get_package_name()}/{service['name']} "
                            f"--es payload 'injected_data'",
                            f"adb shell am start-foreground-service -n {self.apk_parser.get_package_name()}/{service['name']} "
                            f"--es payload 'injected_data'",
                        ]

                        finding = self.create_finding(
                            component_name=service['name'],
                            confidence=Confidence.CONFIRMED,
                            taint_path=[{"method": step.method, "instruction": step.instruction} for step in path.steps],
                            exploit_commands=exploit_cmds,
                            exploit_scenario=f"Attacker can inject data through service intents reaching {sink_pattern}.",
                            api_level_affected="All"
                        )
                        findings.append(finding)

        return findings
