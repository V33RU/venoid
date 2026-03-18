"""Rules for detecting exported Activity vulnerabilities."""

from typing import List, Any, Optional

from .base_rule import BaseRule, Finding, Severity, Confidence
from core.apk_parser import ANDROID_NS


class ExportedActivityRule(BaseRule):
    """Detect exported activities without proper permissions."""

    rule_id = "EXP-001"
    title = "Exported Activity Without Permission"
    severity = Severity.HIGH
    cwe = "CWE-926"
    description = "Activity is exported without requiring a permission, allowing any app to launch it."
    remediation = "Set android:exported=\"false\" or define a signature-level permission."
    references = [
        "https://cwe.mitre.org/data/definitions/926.html",
        "https://developer.android.com/guide/components/activities#Declaring"
    ]

    def check(self) -> List[Finding]:
        """Check for exported activities without permissions."""
        findings = []
        activities = self.apk_parser.get_activities()
        min_sdk = self._safe_sdk_int(self.apk_parser.get_min_sdk())

        for activity in activities:
            if not activity['exported']:
                continue

            # Skip the launcher activity — it is intentionally exported as the app entry point
            is_launcher = any(
                'android.intent.action.MAIN' in f.get('actions', []) and
                'android.intent.category.LAUNCHER' in f.get('categories', [])
                for f in activity.get('intent_filters', [])
            )
            if is_launcher:
                continue

            # Check if protected by signature-level permission
            if self._is_protected(activity.get('permission')):
                continue

            # Determine confidence
            confidence = self._determine_confidence(activity['name'])

            # Generate exploit commands
            exploit_cmds = [
                f"adb shell am start -n {self.apk_parser.get_package_name()}/{activity['name']}",
                f"adb shell am start -a android.intent.action.VIEW -n {self.apk_parser.get_package_name()}/{activity['name']}"
            ]

            finding = self.create_finding(
                component_name=activity['name'],
                confidence=confidence,
                exploit_commands=exploit_cmds,
                exploit_scenario=f"Any malicious app can launch {activity['name']} without restrictions.",
                api_level_affected=f"All (auto-export behavior changed at API 31)" if min_sdk <= 30 else "All"
            )
            findings.append(finding)

        return findings

    def _determine_confidence(self, activity_name: str) -> Confidence:
        """Determine confidence level based on taint analysis."""
        if self.taint_engine:
            # Check if tainted data from this activity reaches a dangerous sink
            for sink_pattern in ["loadUrl", "rawQuery", "execSQL", "exec(", "startActivity", "openFile"]:
                for path in self.taint_engine.get_paths_to_sink(sink_pattern):
                    if activity_name in path.source or activity_name in path.sink:
                        return Confidence.CONFIRMED

        return Confidence.LIKELY


class IntentToWebViewRule(BaseRule):
    """Detect intent data flowing to WebView.loadUrl() - CWE-939."""

    rule_id = "EXP-002"
    title = "Intent Data to WebView Load"
    severity = Severity.CRITICAL
    cwe = "CWE-939"
    description = "User-controlled intent data flows to WebView.loadUrl(), enabling XSS or open redirects."
    remediation = "Validate and sanitize URL data before loading. Use HTTPS allowlists."
    references = [
        "https://cwe.mitre.org/data/definitions/939.html",
        "https://labs.withsecure.com/publications/webview-security"
    ]

    def check(self) -> List[Finding]:
        """Check for taint from getIntent() to loadUrl()."""
        findings = []

        if not self.taint_engine:
            return findings

        # Find paths from getIntent sources to loadUrl sinks
        taint_paths = self.taint_engine.get_paths_to_sink("loadUrl")

        for path in taint_paths:
            exploit_cmds = [
                f"adb shell am start -n {self.apk_parser.get_package_name()}/.Activity --es url 'javascript:alert(1)'",
                f"adb shell am start -n {self.apk_parser.get_package_name()}/.Activity --es url 'https://attacker.com'"
            ]

            finding = self.create_finding(
                component_name=path.sink,
                confidence=Confidence.CONFIRMED if path.confidence == "CONFIRMED" else Confidence.LIKELY,
                taint_path=self._format_taint_path(path),
                exploit_commands=exploit_cmds,
                exploit_scenario="Attacker can inject malicious URLs into WebView via intent extras.",
                api_level_affected="All"
            )
            findings.append(finding)

        return findings


class NestedIntentForwardingRule(BaseRule):
    """Detect StrandHogg 2.0 style nested intent forwarding - CWE-441."""

    rule_id = "EXP-003"
    title = "Nested Intent Forwarding (StrandHogg 2.0)"
    severity = Severity.CRITICAL
    cwe = "CWE-441"
    description = "Activity forwards received intents to other components without validation."
    remediation = "Validate intent data before forwarding. Use explicit intents with FLAG_IMMUTABLE."
    references = [
        "https://cwe.mitre.org/data/definitions/441.html",
        "https://www.promon.io/security-news/strandhogg-2-0"
    ]

    def check(self) -> List[Finding]:
        """Check for intent forwarding patterns."""
        findings = []

        # Search for startActivity/startService with getIntent() data
        forwarding_sinks = ["startActivity", "startService", "startForegroundService"]

        for sink in forwarding_sinks:
            methods = self.callgraph.search_methods(sink) if self.callgraph else []
            for method_sig in methods:
                if "getIntent" in method_sig or "getParcelableExtra" in method_sig:
                    # Check if this is in an exported component
                    for activity in self.apk_parser.get_activities():
                        if activity['exported'] and activity['name'] in method_sig:
                            exploit_cmds = [
                                f"adb shell am start -n {self.apk_parser.get_package_name()}/{activity['name']} "
                                f"--ez android.intent.extra.START_FOREGROUND true"
                            ]

                            finding = self.create_finding(
                                component_name=activity['name'],
                                confidence=Confidence.LIKELY,
                                exploit_commands=exploit_cmds,
                                exploit_scenario="Malicious app can inject intent to be forwarded to privileged components.",
                                api_level_affected="All"
                            )
                            findings.append(finding)

        return findings


class TaskHijackingRule(BaseRule):
    """Detect task hijacking vulnerabilities (StrandHogg)."""

    rule_id = "EXP-020"
    title = "Task Hijacking Vulnerability (StrandHogg)"
    severity = Severity.CRITICAL
    cwe = "CWE-1021"
    description = "Activity allows task hijacking via taskAffinity and allowTaskReparenting."

    def check(self) -> List[Finding]:
        """Check for task hijacking patterns."""
        findings = []

        manifest = self.apk_parser.get_android_manifest_xml()
        if manifest is None:
            return findings

        activities = self.apk_parser.get_activities()

        for activity in activities:
            name = activity.get('name', '')

            if not activity.get('exported', False):
                continue

            launch_mode = self._get_activity_manifest_attr(name, "launchMode")
            task_affinity = self._get_activity_manifest_attr(name, "taskAffinity")

            if launch_mode in ["singleTask", "singleInstance"]:
                findings.append(self.create_finding(
                    component_name=name,
                    confidence=Confidence.LIKELY,
                    details={
                        "issue": "Launch mode allows task hijacking",
                        "launchMode": launch_mode,
                        "taskAffinity": task_affinity
                    },
                    code_snippet=f'android:launchMode="{launch_mode}"',
                    remediation="Avoid singleTask/singleInstance for exported activities. Use standard launchMode.",
                    exploit_commands=[
                        "# StrandHogg attack",
                        "adb shell am start -n malicious.app/.HijackActivity --taskAffinity com.target.app"
                    ]
                ))

        return findings

    def _get_activity_manifest_attr(self, activity_name: str, attr: str) -> Optional[str]:
        """Get a manifest attribute value for a named activity."""
        try:
            manifest = self.apk_parser.get_android_manifest_xml()
            if manifest is None:
                return None
            last_segment = activity_name.split('.')[-1]
            for activity in manifest.findall(".//activity"):
                name = activity.get(f"{{{ANDROID_NS}}}name")
                if name and (name == activity_name or name.endswith(last_segment)):
                    return activity.get(f"{{{ANDROID_NS}}}{attr}")
        except Exception:
            pass
        return None


class TapjackingVulnerabilityRule(BaseRule):
    """Detect tapjacking vulnerabilities."""

    rule_id = "EXP-021"
    title = "Tapjacking Vulnerability"
    severity = Severity.MEDIUM
    cwe = "CWE-1021"
    description = "Activity does not have filterTouchesWhenObscured, making it vulnerable to tapjacking."

    def check(self) -> List[Finding]:
        """Check for tapjacking protection on exported activities.

        Note: filterTouchesWhenObscured is a View layout attribute, not a manifest attribute.
        This rule flags exported activities as POSSIBLE and requires manual verification in
        layout XML files.
        """
        findings = []

        activities = self.apk_parser.get_activities()

        for activity in activities:
            name = activity.get('name', '')

            if not activity.get('exported', False):
                continue

            findings.append(self.create_finding(
                component_name=name,
                confidence=Confidence.POSSIBLE,
                details={
                    "issue": "Exported activity may lack tapjacking protection",
                    "action": "Verify android:filterTouchesWhenObscured=\"true\" in root view layout"
                },
                code_snippet='<!-- Add to root view in layout XML -->\nandroid:filterTouchesWhenObscured="true"',
                remediation="Add filterTouchesWhenObscured=\"true\" to the root view of sensitive activity layouts."
            ))

        return findings


class JavaScriptBridgeRule(BaseRule):
    """Detect insecure JavaScript bridge in WebView."""

    rule_id = "EXP-023"
    title = "Insecure WebView JavaScript Bridge"
    severity = Severity.HIGH
    cwe = "CWE-749"
    description = "WebView has JavaScript enabled with exposed bridge allowing code execution."

    def check(self) -> List[Finding]:
        """Check for WebView JavaScript bridge."""
        findings = []

        if not self.callgraph:
            return findings

        bridge_methods = self.callgraph.search_methods("addJavascriptInterface")

        for method in bridge_methods:
            findings.append(self.create_finding(
                component_name=method.split("->")[0] if "->" in method else "Application",
                confidence=Confidence.CONFIRMED,
                details={
                    "issue": "JavaScript bridge exposed",
                    "method": method
                },
                code_snippet="webView.addJavascriptInterface(new JsBridge(), \"Android\");",
                remediation="Remove @JavascriptInterface methods or validate origin. Use Chrome Custom Tabs instead.",
                exploit_commands=["# Inject JavaScript", "javascript:Android.method(args)"]
            ))

        return findings
