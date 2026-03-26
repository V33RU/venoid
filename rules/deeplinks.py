"""Rules for detecting Deep Link vulnerabilities."""

from typing import List, Dict, Any

from .base_rule import BaseRule, Finding, Severity, Confidence


class DeepLinkAutoVerifyRule(BaseRule):
    """Detect deep links without autoVerify - CWE-345."""

    rule_id = "EXP-013"
    title = "Deep Link Without autoVerify"
    severity = Severity.MEDIUM
    cwe = "CWE-345"
    component_type = "deeplink"
    description = "Intent filter handles custom scheme without android:autoVerify=\"true\", enabling phishing via link hijacking."
    remediation = "Set android:autoVerify=\"true\" for all intent filters handling https:// or use App Links."
    references = (
        "https://cwe.mitre.org/data/definitions/345.html",
        "https://developer.android.com/training/app-links/verify-site-associations"
    )

    def check(self) -> List[Finding]:
        """Check for deep links without autoVerify."""
        findings = []
        components = self.apk_parser.get_activities() + self.apk_parser.get_services()

        for component in components:
            if self._is_third_party_component(component['name']):
                continue
            for intent_filter in component.get('intent_filters', []):
                schemes = [d.get('scheme', '') for d in intent_filter.get('data', [])]

                # Check if handling http/https without autoVerify
                if 'http' in schemes or 'https' in schemes:
                    has_autoverify = self._check_autoverify(component['name'], intent_filter)

                    if not has_autoverify:
                        exploit_cmds = [
                            f"adb shell am start -a android.intent.action.VIEW -d 'https://phishing.com/malicious' "
                            f"-n {self.apk_parser.get_package_name()}/{component['name']}"
                        ]

                        finding = self.create_finding(
                            component_name=component['name'],
                            confidence=Confidence.LIKELY,
                            exploit_commands=exploit_cmds,
                            exploit_scenario="Malicious app can intercept links intended for legitimate domains.",
                            api_level_affected="All"
                        )
                        findings.append(finding)

        return findings

    def _check_autoverify(self, activity_name: str, intent_filter: Dict[str, Any]) -> bool:
        """Check if autoVerify is set on intent filter."""
        return intent_filter.get('autoVerify', False) is True


class DeepLinkOpenRedirectRule(BaseRule):
    """Detect deep links that redirect to arbitrary URLs - CWE-601."""

    rule_id = "EXP-014"
    title = "Deep Link Open Redirect"
    severity = Severity.MEDIUM
    cwe = "CWE-601"
    component_type = "deeplink"
    description = "Deep link parameter flows directly to startActivity() without validation, enabling open redirects."
    remediation = "Validate redirect URLs against an allowlist. Reject arbitrary external redirects."
    references = (
        "https://cwe.mitre.org/data/definitions/601.html",
        "https://developer.android.com/training/app-links/deep-linking"
    )

    def check(self) -> List[Finding]:
        """Check for open redirect vulnerabilities in deep links."""
        findings = []

        if not self.taint_engine:
            return findings

        components = self.apk_parser.get_activities() + self.apk_parser.get_services()

        for component in components:
            if self._is_third_party_component(component['name']):
                continue
            has_deep_link = False
            for intent_filter in component.get('intent_filters', []):
                schemes = [d.get('scheme', '') for d in intent_filter.get('data', [])]
                if schemes:
                    has_deep_link = True
                    break

            if not has_deep_link:
                continue

            # Check for taint from getData() to startActivity
            paths = self.taint_engine.get_paths_to_sink("startActivity")

            for path in paths:
                if "getData" in path.source or "getQueryParameter" in path.source:
                    if component['name'] in path.sink:
                        exploit_cmds = [
                            f"adb shell am start -a android.intent.action.VIEW "
                            f"-d 'app://open?url=https://attacker.com/phishing' "
                            f"-n {self.apk_parser.get_package_name()}/{component['name']}",
                            f"adb shell am start -a android.intent.action.VIEW "
                            f"-d 'app://redirect?target=javascript:alert(1)' "
                            f"-n {self.apk_parser.get_package_name()}/{component['name']}"
                        ]

                        finding = self.create_finding(
                            component_name=component['name'],
                            confidence=Confidence.CONFIRMED,
                            taint_path=[{"method": step.method, "instruction": step.instruction} for step in path.steps],
                            exploit_commands=exploit_cmds,
                            exploit_scenario="Attacker can redirect users to arbitrary URLs or execute JavaScript.",
                            api_level_affected="All"
                        )
                        findings.append(finding)

        return findings


class CustomSchemeHijackingRule(BaseRule):
    """Detect custom URL schemes that can be hijacked."""

    rule_id = "EXP-015"
    title = "Custom URL Scheme Hijacking"
    severity = Severity.MEDIUM
    cwe = "CWE-346"
    component_type = "deeplink"
    description = "App registers custom URL scheme (e.g., myapp://) without verification, allowing other apps to intercept."
    remediation = "Use App Links with autoVerify. Avoid custom schemes for sensitive operations."
    references = (
        "https://cwe.mitre.org/data/definitions/346.html",
        "https://developer.android.com/training/app-links/deep-linking"
    )

    def check(self) -> List[Finding]:
        """Check for custom scheme vulnerabilities."""
        findings = []
        components = self.apk_parser.get_activities() + self.apk_parser.get_services()

        common_schemes = ['http', 'https', 'file', 'content', 'javascript']

        for component in components:
            if self._is_third_party_component(component['name']):
                continue
            for intent_filter in component.get('intent_filters', []):
                data_specs = intent_filter.get('data', [])

                for spec in data_specs:
                    scheme = spec.get('scheme', '')
                    if scheme and scheme not in common_schemes:
                        exploit_cmds = [
                            f"adb shell am start -a android.intent.action.VIEW "
                            f"-d '{scheme}://test/payload' "
                            f"-n {self.apk_parser.get_package_name()}/{component['name']}",
                            f"adb shell am start -a android.intent.action.VIEW "
                            f"-d '{scheme}://open?token=test_token' "
                            f"-n {self.apk_parser.get_package_name()}/{component['name']}"
                        ]

                        finding = self.create_finding(
                            component_name=component['name'],
                            confidence=Confidence.LIKELY,
                            exploit_commands=exploit_cmds,
                            exploit_scenario=f"Any app can register for {scheme}:// scheme and intercept deep links.",
                            api_level_affected="All"
                        )
                        findings.append(finding)

        return findings
