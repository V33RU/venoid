"""Rules for detecting exported Broadcast Receiver vulnerabilities."""

from typing import List

from .base_rule import BaseRule, Finding, Severity, Confidence, dalvik_to_java


class ExportedReceiverRule(BaseRule):
    """Detect exported broadcast receivers without proper permissions."""

    rule_id = "EXP-006"
    title = "Exported Broadcast Receiver Without Permission"
    severity = Severity.HIGH
    cwe = "CWE-925"
    description = "Broadcast receiver is exported without requiring a permission, allowing any app to send broadcasts to it."
    remediation = "Set android:exported=\"false\" or define a signature-level permission."
    references = (
        "https://cwe.mitre.org/data/definitions/925.html",
        "https://developer.android.com/guide/components/broadcasts#security"
    )

    def check(self) -> List[Finding]:
        """Check for exported receivers without permissions."""
        findings = []
        receivers = self.apk_parser.get_receivers()

        for receiver in receivers:
            if not receiver['exported']:
                continue

            # Skip known third-party SDK receivers - they are legitimately exported
            if self._is_third_party_component(receiver['name']):
                continue

            # Check if protected by signature-level permission
            if self._is_protected(receiver.get('permission')):
                continue

            pkg = self.apk_parser.get_package_name()
            exploit_cmds = [
                f"adb shell am broadcast -n {pkg}/{receiver['name']}",
            ]
            # Use actual registered actions instead of a hardcoded placeholder
            for intent_filter in receiver.get('intent_filters', []):
                for action in intent_filter.get('actions', []):
                    exploit_cmds.append(
                        f"adb shell am broadcast -a {action} -n {pkg}/{receiver['name']}"
                    )

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
    references = (
        "https://developer.android.com/about/versions/13/behavior-changes-13#runtime-received-broadcasts",
    )

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

        if not self.callgraph:
            return findings

        # Find callers of registerReceiver - these are the methods that register a receiver.
        # For each caller, check whether it (or any of its callees) reference the
        # RECEIVER_NOT_EXPORTED / RECEIVER_EXPORTED constant.  The constant is accessed as
        # a field read of android.content.Context, so we look for it in the caller's own
        # callees and in the method signature of the callers themselves.
        callers = self.callgraph.search_methods("registerReceiver")
        seen: set = set()

        for caller_sig in callers:
            if caller_sig in seen:
                continue
            seen.add(caller_sig)

            # Collect the full set of strings associated with this call site:
            # the caller signature + its direct callees
            callees = self.callgraph.get_callees(caller_sig)
            context_strings = [caller_sig] + list(callees)

            has_export_flag = any(
                "RECEIVER_NOT_EXPORTED" in s or "RECEIVER_EXPORTED" in s
                for s in context_strings
            )
            if has_export_flag:
                continue

            # Derive a human-readable class name for the finding
            class_name = dalvik_to_java(caller_sig)

            finding = self.create_finding(
                component_name=class_name,
                confidence=Confidence.POSSIBLE,
                code_snippet=(
                    "// registerReceiver() called without RECEIVER_NOT_EXPORTED flag\n"
                    "// context.registerReceiver(receiver, filter);  // API 33+ requires explicit export flag\n"
                    "// Fix: context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED);"
                ),
                exploit_commands=[
                    "# Dynamic receiver - determine the registered action at runtime (e.g. via Frida or logcat)",
                    "# Then broadcast with: adb shell am broadcast -a <action> --receiver-include-background",
                    "# Example if action is known:",
                    "# adb shell am broadcast -a com.example.CUSTOM_ACTION --receiver-include-background",
                ],
                exploit_scenario=(
                    f"{class_name} registers a BroadcastReceiver without explicitly passing "
                    "Context.RECEIVER_NOT_EXPORTED. On API 33+ this defaults to exported, "
                    "allowing any app to send broadcasts to it."
                ),
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
    references = (
        "https://cwe.mitre.org/data/definitions/20.html",
        "https://developer.android.com/guide/components/broadcasts#security"
    )

    def check(self) -> List[Finding]:
        """Check for taint flow in exported receivers."""
        findings = []

        if not self.taint_engine:
            return findings

        receivers = self.apk_parser.get_receivers()

        seen: set = set()
        for receiver in receivers:
            if not receiver['exported']:
                continue

            # Check for taint paths from this receiver's class to dangerous sinks
            dangerous_sinks = ["exec(", "rawQuery", "execSQL", "loadUrl", "openFile", "startActivity"]
            for sink_pattern in dangerous_sinks:
                for path in self.taint_engine.get_paths_to_sink(sink_pattern):
                    if receiver['name'] in path.source or receiver['name'] in path.sink:
                        key = (receiver['name'], sink_pattern)
                        if key in seen:
                            continue
                        seen.add(key)

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


class UnprotectedSendBroadcastRule(BaseRule):
    """Detect sendBroadcast() calls that omit the receiverPermission argument - CWE-927."""

    rule_id = "EXP-039"
    title = "Unprotected Outgoing Broadcast"
    severity = Severity.MEDIUM
    cwe = "CWE-927"
    component_type = "receiver"
    description = (
        "Application sends a broadcast without specifying a receiverPermission argument. "
        "Any installed app that declares the matching intent-filter can receive this broadcast "
        "and intercept the data it carries (tokens, URLs, commands, etc.)."
    )
    remediation = (
        "Use sendBroadcast(intent, receiverPermission) and declare a signature-level permission. "
        "For intra-app communication use LocalBroadcastManager or an explicit intent instead."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/927.html",
        "https://developer.android.com/guide/components/broadcasts#restricting_broadcasts_with_permissions",
    )

    def check(self) -> List[Finding]:
        findings = []

        if not self.callgraph:
            return findings

        pkg = self.apk_parser.get_package_name()
        seen: set = set()

        for caller_sig in self.callgraph.search_methods("sendBroadcast"):
            if caller_sig in seen:
                continue
            seen.add(caller_sig)

            # Skip third-party SDK callers
            class_name = dalvik_to_java(caller_sig)
            if self._is_third_party_component(class_name):
                continue

            # Check callees for a permission string being passed (signature-level guard)
            callees = self.callgraph.get_callees(caller_sig)
            has_permission_arg = any(
                "permission" in c.lower() or "signature" in c.lower()
                for c in callees
            )
            confidence = Confidence.POSSIBLE if has_permission_arg else Confidence.LIKELY

            findings.append(self.create_finding(
                component_name=class_name or "Application",
                confidence=confidence,
                code_snippet=(
                    "// Unprotected - any app can receive this:\n"
                    "sendBroadcast(intent);\n\n"
                    "// Fix - restrict to apps holding this permission:\n"
                    "sendBroadcast(intent, \"com.example.RECEIVE_BROADCAST\");"
                ),
                exploit_commands=[
                    "# Register a receiver for the broadcast action in a malicious app",
                    "# AndroidManifest.xml in attacker app:",
                    "# <receiver android:name='.SnoopReceiver'>",
                    "#   <intent-filter><action android:name='<observed_action>'/></intent-filter>",
                    "# </receiver>",
                    "# Any extras in the broadcast (tokens, URLs, commands) will be delivered",
                ],
                exploit_scenario=(
                    f"{class_name} sends a broadcast without a receiver permission. "
                    "A malicious app can register the same intent-filter and silently "
                    "intercept all data carried in the broadcast extras."
                ),
                api_level_affected="All",
            ))

        return findings


class StickyBroadcastRule(BaseRule):
    """Detect use of deprecated sendStickyBroadcast - CWE-925."""

    rule_id = "EXP-040"
    title = "Sticky Broadcast Usage"
    severity = Severity.MEDIUM
    cwe = "CWE-925"
    component_type = "receiver"
    description = (
        "Application uses sendStickyBroadcast(), which is deprecated since API 21. "
        "Sticky broadcasts persist in the system after delivery; any app can retrieve "
        "the last value via registerReceiver(null, filter) without ever having registered "
        "a receiver, leaking whatever data was placed in the intent."
    )
    remediation = (
        "Replace sendStickyBroadcast() with a non-sticky broadcast plus an explicit "
        "receiver, or use a shared data store (ViewModel, database, SharedPreferences) "
        "protected by appropriate access controls."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/925.html",
        "https://developer.android.com/reference/android/content/Context#sendStickyBroadcast(android.content.Intent)",
    )

    def check(self) -> List[Finding]:
        findings = []

        if not self.callgraph:
            return findings

        seen: set = set()

        for caller_sig in self.callgraph.search_methods("sendStickyBroadcast"):
            if caller_sig in seen:
                continue
            seen.add(caller_sig)

            class_name = dalvik_to_java(caller_sig)
            if self._is_third_party_component(class_name):
                continue

            findings.append(self.create_finding(
                component_name=class_name or "Application",
                confidence=Confidence.CONFIRMED,
                code_snippet=(
                    "// Deprecated and insecure:\n"
                    "sendStickyBroadcast(intent);\n\n"
                    "// Any app can silently retrieve the last sticky broadcast:\n"
                    "Intent last = registerReceiver(null, new IntentFilter(\"<action>\"));"
                ),
                exploit_commands=[
                    "# Retrieve last sticky broadcast value from any app (no permission needed):",
                    "# Intent data = context.registerReceiver(null, new IntentFilter(\"<observed_action>\"));",
                    "# Log.d(\"steal\", data.getStringExtra(\"token\"));",
                    "# Or via adb with a test app - no special permission required",
                ],
                exploit_scenario=(
                    f"{class_name} sends a sticky broadcast. An attacker app can call "
                    "registerReceiver(null, intentFilter) at any time - even after the "
                    "broadcast was sent - and retrieve all extras from the last sticky intent."
                ),
                api_level_affected="All (deprecated since API 21)",
            ))

        return findings
