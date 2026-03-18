"""Rules for detecting exported Content Provider vulnerabilities."""

from typing import List

from .base_rule import BaseRule, Finding, Severity, Confidence


class ExportedProviderRule(BaseRule):
    """Detect exported content providers with partial permissions."""

    rule_id = "EXP-009"
    title = "Exported Content Provider Without Proper Permission"
    severity = Severity.HIGH
    cwe = "CWE-732"
    description = "Content provider is exported without requiring a permission for both read and write operations."
    remediation = "Set android:exported=\"false\" or define signature-level read/write permissions."
    references = [
        "https://cwe.mitre.org/data/definitions/732.html",
        "https://developer.android.com/guide/topics/providers/content-provider-creating"
    ]

    def check(self) -> List[Finding]:
        """Check for exported providers without full permission protection."""
        findings = []
        providers = self.apk_parser.get_providers()

        for provider in providers:
            if not provider['exported']:
                continue

            # Check for partial permissions
            read_perm = provider.get('read_permission')
            write_perm = provider.get('write_permission')
            general_perm = provider.get('permission')

            # If only read or only write permission is set, it's vulnerable
            has_full_protection = (
                self._is_protected(read_perm) and self._is_protected(write_perm)
            ) or self._is_protected(general_perm)

            if has_full_protection:
                continue

            for authority in provider.get('authorities', []):
                exploit_cmds = [
                    f"adb shell content query --uri content://{authority}/",
                    f"adb shell content read --uri content://{authority}/",
                    f"adb shell content query --uri content://{authority}/ --where \"1=1\" --sort \"name ASC\"",
                ]

                finding = self.create_finding(
                    component_name=f"{provider['name']} ({authority})",
                    confidence=Confidence.LIKELY,
                    exploit_commands=exploit_cmds,
                    exploit_scenario=f"Any app can query or modify content provider {authority}.",
                    api_level_affected="All"
                )
                findings.append(finding)

        return findings


class ProviderSQLInjectionRule(BaseRule):
    """Detect SQL injection vulnerabilities in content providers - CWE-89."""

    rule_id = "EXP-010"
    title = "Content Provider SQL Injection"
    severity = Severity.CRITICAL
    cwe = "CWE-89"
    description = "Content provider constructs SQL queries using unsanitized user input from selection parameter."
    remediation = "Use parameterized queries or query builder. Never concatenate user input into SQL."
    references = [
        "https://cwe.mitre.org/data/definitions/89.html",
        "https://developer.android.com/guide/topics/providers/content-provider-creating#Implementation"
    ]

    def check(self) -> List[Finding]:
        """Check for SQL injection in provider query methods."""
        findings = []

        if not self.taint_engine:
            return findings

        providers = self.apk_parser.get_providers()

        for provider in providers:
            if not provider['exported']:
                continue

            # Check for taint paths from selection parameter to rawQuery/execSQL
            paths = self.taint_engine.get_paths_to_sink("rawQuery")
            paths.extend(self.taint_engine.get_paths_to_sink("execSQL"))

            for path in paths:
                if "query" in path.source.lower() or "selection" in path.source.lower():
                    for authority in provider.get('authorities', []):
                        exploit_cmds = [
                            f"adb shell content query --uri content://{authority}/ "
                            f"--where \"1=1 OR 1=1\"",
                            f"adb shell content query --uri content://{authority}/ "
                            f"--where \"name=' OR '1'='1\"",
                        ]

                        finding = self.create_finding(
                            component_name=f"{provider['name']} ({authority})",
                            confidence=Confidence.CONFIRMED,
                            taint_path=[{"method": step.method, "instruction": step.instruction} for step in path.steps],
                            exploit_commands=exploit_cmds,
                            exploit_scenario=f"Attacker can execute arbitrary SQL queries against {authority}.",
                            api_level_affected="All"
                        )
                        findings.append(finding)

        return findings


class ProviderPathTraversalRule(BaseRule):
    """Detect path traversal in openFile() methods - CWE-22."""

    rule_id = "EXP-011"
    title = "Content Provider Path Traversal"
    severity = Severity.HIGH
    cwe = "CWE-22"
    description = "Content provider's openFile() method allows path traversal via unsanitized URI path segments."
    remediation = "Validate and sanitize URI paths. Use canonical paths and check against allowed directories."
    references = [
        "https://cwe.mitre.org/data/definitions/22.html",
        "https://developer.android.com/reference/android/content/ContentProvider#openFile(android.net.Uri,%20java.lang.String)"
    ]

    def check(self) -> List[Finding]:
        """Check for path traversal vulnerabilities in provider openFile."""
        findings = []

        if not self.taint_engine:
            return findings

        providers = self.apk_parser.get_providers()

        for provider in providers:
            if not provider['exported']:
                continue

            # Check for taint paths to openFile
            paths = self.taint_engine.get_paths_to_sink("openFile")

            for path in paths:
                if provider['name'] in path.source or provider['name'] in path.sink:
                    for authority in provider.get('authorities', []):
                        exploit_cmds = [
                            f"adb shell content read --uri content://{authority}/../../../etc/passwd",
                            f"adb shell content read --uri content://{authority}/%2F..%2F..%2F..%2Fdata%2Fdata%2F",
                            f"adb shell 'content call --uri content://{authority}/../../../../data/data/package/databases/app.db'"
                        ]

                        finding = self.create_finding(
                            component_name=f"{provider['name']} ({authority})",
                            confidence=Confidence.CONFIRMED,
                            taint_path=[{"method": step.method, "instruction": step.instruction} for step in path.steps],
                            exploit_commands=exploit_cmds,
                            exploit_scenario=f"Attacker can read arbitrary files via {authority} using path traversal.",
                            api_level_affected="All"
                        )
                        findings.append(finding)

        return findings


class GrantUriPermissionsRule(BaseRule):
    """Detect global URI permission grants - CWE-284."""

    rule_id = "EXP-012"
    title = "Global URI Permission Grant"
    severity = Severity.HIGH
    cwe = "CWE-284"
    description = "Content provider has android:grantUriPermissions=\"true\" allowing any app to access URIs."
    remediation = "Set android:grantUriPermissions=\"false\" or use per-URI grants with explicit permissions."
    references = [
        "https://cwe.mitre.org/data/definitions/284.html",
        "https://developer.android.com/guide/topics/providers/content-provider-creating#Permissions"
    ]

    def check(self) -> List[Finding]:
        """Check for global grantUriPermissions."""
        findings = []
        providers = self.apk_parser.get_providers()

        for provider in providers:
            grant_global = provider.get('grant_uri_permissions')
            if not grant_global or str(grant_global).lower() != 'true':
                continue

            for authority in provider.get('authorities', []):
                exploit_cmds = [
                    f"adb shell content call --uri content://{authority}/ --method grant_uri_permission"
                ]

                finding = self.create_finding(
                    component_name=f"{provider['name']} ({authority})",
                    confidence=Confidence.LIKELY,
                    exploit_commands=exploit_cmds,
                    exploit_scenario=f"Any app can request and obtain temporary access to URIs from {authority}.",
                    api_level_affected="All"
                )
                findings.append(finding)

        return findings
