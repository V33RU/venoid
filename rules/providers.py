"""Rules for detecting exported Content Provider vulnerabilities."""

from typing import List
from xml.etree import ElementTree

from .base_rule import BaseRule, Finding, Severity, Confidence


class ExportedProviderRule(BaseRule):
    """Detect exported content providers with partial permissions."""

    rule_id = "EXP-009"
    title = "Exported Content Provider Without Proper Permission"
    severity = Severity.HIGH
    cwe = "CWE-732"
    description = "Content provider is exported without requiring a permission for both read and write operations."
    remediation = "Set android:exported=\"false\" or define signature-level read/write permissions."
    references = (
        "https://cwe.mitre.org/data/definitions/732.html",
        "https://developer.android.com/guide/topics/providers/content-provider-creating"
    )

    def check(self) -> List[Finding]:
        """Check for exported providers without full permission protection."""
        findings = []
        providers = self.apk_parser.get_providers()

        for provider in providers:
            if not provider['exported']:
                continue

            # Check for partial permissions
            read_perm = provider.get('readPermission')
            write_perm = provider.get('writePermission')
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
    references = (
        "https://cwe.mitre.org/data/definitions/89.html",
        "https://developer.android.com/guide/topics/providers/content-provider-creating#Implementation"
    )

    def check(self) -> List[Finding]:
        """Check for SQL injection in provider query methods."""
        findings = []

        if not self.taint_engine:
            return findings

        providers = self.apk_parser.get_providers()

        # Check for taint paths from selection parameter to rawQuery/execSQL
        paths = self.taint_engine.get_paths_to_sink("rawQuery")
        paths.extend(self.taint_engine.get_paths_to_sink("execSQL"))

        seen: set = set()
        for provider in providers:
            if not provider['exported']:
                continue

            for path in paths:
                if "query" in path.source.lower() or "selection" in path.source.lower():
                    for authority in provider.get('authorities', []):
                        key = (provider['name'], authority)
                        if key in seen:
                            continue
                        seen.add(key)

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
    references = (
        "https://cwe.mitre.org/data/definitions/22.html",
        "https://developer.android.com/reference/android/content/ContentProvider#openFile(android.net.Uri,%20java.lang.String)"
    )

    def check(self) -> List[Finding]:
        """Check for path traversal vulnerabilities in provider openFile."""
        findings = []

        if not self.taint_engine:
            return findings

        providers = self.apk_parser.get_providers()

        # Check for taint paths to openFile
        paths = self.taint_engine.get_paths_to_sink("openFile")

        seen: set = set()
        for provider in providers:
            if not provider['exported']:
                continue

            for path in paths:
                if provider['name'] in path.source or provider['name'] in path.sink:
                    for authority in provider.get('authorities', []):
                        key = (provider['name'], authority)
                        if key in seen:
                            continue
                        seen.add(key)

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


class TypoPermissionRule(BaseRule):
    """Detect content providers protected by a permission that was never declared - CWE-732.

    A common mistake is setting android:permission (or readPermission/writePermission)
    to a string that is misspelled or never declared.  Android treats an undeclared
    permission as always-granted, so the provider is effectively unprotected.
    """

    rule_id = "EXP-032"
    title = "Content Provider Protected by Undeclared Permission (Typo Permission)"
    severity = Severity.CRITICAL
    cwe = "CWE-732"
    description = (
        "Content provider references a permission string that is not declared in the "
        "manifest. Android grants access to any app when the required permission does "
        "not exist, making the provider completely unprotected despite the attribute."
    )
    remediation = (
        "Declare the permission with <permission> in AndroidManifest.xml and set "
        "android:protectionLevel=\"signature\". Verify the exact permission string matches."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/732.html",
        "https://developer.android.com/guide/topics/manifest/permission-element",
    )

    def check(self) -> List[Finding]:
        findings = []

        declared = {p["name"] for p in self.apk_parser.get_custom_permissions()}
        # Also include well-known Android platform permissions as valid
        # (we only want to catch custom/app-defined permissions that are typo'd)

        providers = self.apk_parser.get_providers()
        for provider in providers:
            if not provider["exported"]:
                continue

            for perm_attr in ("permission", "readPermission", "writePermission"):
                perm = provider.get(perm_attr)
                if not perm:
                    continue
                # Only flag custom permissions (not android.permission.*)
                if perm.startswith("android.permission."):
                    continue
                # If the permission is referenced but never declared → typo
                if perm not in declared:
                    for authority in provider.get("authorities", []):
                        findings.append(self.create_finding(
                            component_name=f"{provider['name']} ({authority})",
                            confidence=Confidence.CONFIRMED,
                            code_snippet=f'android:{perm_attr}="{perm}"  <!-- NOT declared in manifest -->',
                            exploit_commands=[
                                f"adb shell content query --uri content://{authority}/",
                                f"adb shell content read --uri content://{authority}/",
                            ],
                            exploit_scenario=(
                                f"Permission '{perm}' is referenced but never declared. "
                                f"Any app can access {authority} without holding any permission."
                            ),
                            api_level_affected="All",
                        ))

        return findings


class GrantUriPermissionsRule(BaseRule):
    """Detect global URI permission grants - CWE-284."""

    rule_id = "EXP-012"
    title = "Global URI Permission Grant"
    severity = Severity.HIGH
    cwe = "CWE-284"
    description = "Content provider has android:grantUriPermissions=\"true\" allowing any app to access URIs."
    remediation = "Set android:grantUriPermissions=\"false\" or use per-URI grants with explicit permissions."
    references = (
        "https://cwe.mitre.org/data/definitions/284.html",
        "https://developer.android.com/guide/topics/providers/content-provider-creating#Permissions"
    )

    def check(self) -> List[Finding]:
        """Check for global grantUriPermissions."""
        findings = []
        providers = self.apk_parser.get_providers()

        for provider in providers:
            grant_global = provider.get('grantUriPermissions')
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


class FileProviderBroadPathsRule(BaseRule):
    """Detect FileProvider exposing overly broad paths - CWE-200."""

    rule_id = "EXP-038"
    title = "FileProvider Exposes Broad File Paths"
    severity = Severity.HIGH
    cwe = "CWE-200"
    component_type = "provider"
    description = (
        "FileProvider's paths configuration includes overly broad entries "
        "(root-path, or a path of '.' / '/') that expose the entire filesystem "
        "or all app private data to any app that receives a URI grant."
    )
    remediation = (
        "Restrict FileProvider paths to only the specific subdirectory that "
        "needs to be shared. Avoid <root-path> entirely. Use <files-path> / "
        "<cache-path> with an explicit subdirectory instead of path=\".\"."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/200.html",
        "https://developer.android.com/reference/androidx/core/content/FileProvider",
        "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md",
    )

    # Tags that are inherently dangerous regardless of the path value
    _ALWAYS_DANGEROUS_TAGS = {"root-path", "external-path"}

    # Tags that are dangerous only when path="." or path="/" (exposes whole directory)
    _BROAD_PATH_TAGS = {
        "files-path", "cache-path",
        "external-files-path", "external-cache-path",
        "external-media-path",
    }

    # Path values that mean "everything in this directory"
    _BROAD_PATH_VALUES = {".", "/", "", None}

    def check(self) -> List[Finding]:
        findings = []

        providers = self.apk_parser.get_providers()
        pkg = self.apk_parser.get_package_name()

        for provider in providers:
            name = provider["name"]

            # Only look at FileProvider subclasses
            if "FileProvider" not in name and "fileprovider" not in name.lower():
                continue

            # Exported FileProviders are the attack surface (unexported ones still
            # require an explicit URI grant so the risk is lower).
            is_exported = provider.get("exported", False)

            paths_xml = self.apk_parser.get_file_provider_paths(name)
            if not paths_xml:
                if is_exported:
                    # Can't read paths XML but it's exported — flag as POSSIBLE
                    for authority in provider.get("authorities", []):
                        findings.append(self.create_finding(
                            component_name=f"{name} ({authority})",
                            confidence=Confidence.POSSIBLE,
                            code_snippet="<!-- Unable to read file_paths.xml from APK — review manually -->",
                            exploit_commands=[
                                f"# Decode APK and inspect res/xml/file_paths.xml",
                                f"apktool d app.apk -o app_decoded",
                                f"cat app_decoded/res/xml/file_paths.xml",
                            ],
                            exploit_scenario=(
                                f"FileProvider {name} is exported but its paths XML could not "
                                f"be parsed. Manually verify that no broad paths are configured."
                            ),
                            api_level_affected="All",
                        ))
                continue

            # Parse the paths XML
            try:
                root = ElementTree.fromstring(paths_xml)
            except ElementTree.ParseError:
                continue

            dangerous_entries: List[str] = []

            for child in root:
                tag = child.tag.lower().lstrip("{}")
                # Strip any namespace
                if "}" in child.tag:
                    tag = child.tag.split("}")[1].lower()

                path_val = child.get("path", None)
                name_attr = child.get("name", "")

                if tag in self._ALWAYS_DANGEROUS_TAGS:
                    dangerous_entries.append(
                        f"<{tag} name=\"{name_attr}\" path=\"{path_val}\">"
                        f"  <!-- exposes broad filesystem area -->"
                    )
                elif tag in self._BROAD_PATH_TAGS and path_val in self._BROAD_PATH_VALUES:
                    dangerous_entries.append(
                        f"<{tag} name=\"{name_attr}\" path=\"{path_val or '.'}\"> "
                        f"  <!-- exposes entire {tag} directory -->"
                    )

            if not dangerous_entries:
                continue

            snippet = "<!-- res/xml/file_paths.xml -->\n<paths>\n"
            for entry in dangerous_entries:
                snippet += f"    {entry}\n"
            snippet += "</paths>"

            for authority in provider.get("authorities", []):
                findings.append(self.create_finding(
                    component_name=f"{name} ({authority})",
                    confidence=Confidence.CONFIRMED,
                    code_snippet=snippet,
                    exploit_commands=[
                        f"# Request a URI grant to a sensitive file via the overly-broad FileProvider",
                        f"adb shell content call --uri content://{authority}/root/data/data/{pkg}/databases/app.db "
                        f"--method getFileDescriptor",
                        f"# Or trigger via a malicious app that requests a URI grant:",
                        f"# Intent intent = new Intent(Intent.ACTION_VIEW);",
                        f"# intent.setData(Uri.parse(\"content://{authority}/root/data/data/{pkg}/shared_prefs/creds.xml\"));",
                        f"# context.startActivity(intent);",
                    ],
                    exploit_scenario=(
                        f"FileProvider {name} exposes broad paths in its XML configuration. "
                        f"Any app that receives a URI grant (or if the provider is exported) "
                        f"can read sensitive files including databases, shared preferences, and tokens."
                    ),
                    api_level_affected="All",
                ))

        return findings
