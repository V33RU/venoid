"""Rules for detecting cryptographic and code-quality vulnerabilities."""

import re
from typing import List

from .base_rule import BaseRule, Finding, Severity, Confidence, dalvik_to_java


class HardcodedCryptoKeyRule(BaseRule):
    """Detect hardcoded cryptographic keys in code."""

    rule_id = "EXP-016"
    title = "Hardcoded Cryptographic Key"
    severity = Severity.CRITICAL
    cwe = "CWE-798"
    description = "Cryptographic keys are hardcoded in the application, allowing extraction and misuse."

    # Strings that contain crypto keyword names but are NOT keys — they are
    # algorithm/mode/padding specs, class names, or log messages.
    _BENIGN_PATTERNS = (
        # JCA algorithm spec strings  (e.g. "AES/CBC/PKCS5Padding")
        "/cbc/", "/ecb/", "/gcm/", "/cfb/", "/ofb/", "/ctr/",
        "pkcs5", "pkcs7", "nopadding", "iso10126",
        # Common class / package path fragments
        "javax.crypto", "java.security", "android.security",
        "secretkeyspec", "secretkeyfactory", "keygenerator",
        "keystore", "keypairgen", "keyagreement",
        "rsaengine", "aesengine", "desengine",
        # Bouncycastle / conscrypt internal names
        "org.bouncycastle", "com.android.org",
        # Log / exception messages that mention key type by name
        "invalidkeyexception", "nosuchalgorithmexception",
        "illegalblocksizeexception", "badpaddingexception",
        # Resource / config keys (very short tokens that match "key" literally)
        "apikey_placeholder", "your_api_key", "insert_key_here",
        "todo", "fixme", "example", "test", "demo", "sample",
    )

    # Only flag strings that look like they could be literal key material:
    # base64 blobs, hex strings, or high-entropy alphanumeric strings.
    _KEY_VALUE_PATTERNS = [
        # Base64 key material (at least 24 chars, only base64 chars, ends with = optional)
        re.compile(r'^[A-Za-z0-9+/]{24,}={0,2}$'),
        # Hex string (at least 32 hex chars = 128-bit key)
        re.compile(r'^[0-9a-fA-F]{32,}$'),
        # High-entropy alphanumeric (letters + digits, no spaces, ≥20 chars)
        re.compile(r'^[A-Za-z0-9_\-]{20,}$'),
    ]

    def check(self) -> List[Finding]:
        """Check for hardcoded keys in strings."""
        findings = []

        # Keywords whose *presence in a string value* suggests a hardcoded secret.
        # We look for strings that both (a) match a key-value pattern AND (b) are
        # assigned to a variable / field whose name contains one of these words.
        # Since we only have the string pool, we use the string value itself as
        # the heuristic — a pure value match.
        key_label_patterns = [
            "secret", "private_key", "api_key", "apikey",
            "api-secret", "privatekey", "access_key", "auth_token",
            "client_secret", "signing_key", "encryption_key",
        ]

        if not (hasattr(self.apk_parser, 'apk') and self.apk_parser.apk):
            return findings

        strings = set()
        try:
            for dex in self.apk_parser.apk.get_all_dex():
                if hasattr(dex, 'get_strings'):
                    strings.update(dex.get_strings())
        except Exception:
            pass

        seen: set = set()
        for string in strings:
            s = str(string).strip()
            s_lower = s.lower()

            # Skip short strings — too short to be a real key
            if len(s) < 16:
                continue

            # Skip known benign patterns immediately
            if any(bp in s_lower for bp in self._BENIGN_PATTERNS):
                continue

            # Skip strings with spaces — keys don't have spaces
            if ' ' in s:
                continue

            # The string itself must look like key material
            if not self._matches_key_value(s):
                continue

            # Optionally: string contains a label keyword (extra signal)
            has_label = any(kw in s_lower for kw in key_label_patterns)
            confidence = Confidence.LIKELY if has_label else Confidence.POSSIBLE

            key = s[:60]
            if key in seen:
                continue
            seen.add(key)

            findings.append(self.create_finding(
                component_name="Application",
                confidence=confidence,
                details={"hardcoded_string": s[:80] + ("..." if len(s) > 80 else "")},
                code_snippet=f'String key = "{s[:80]}{"..." if len(s) > 80 else ""}";',
                remediation="Use Android Keystore or secure key management. Never hardcode cryptographic keys.",
                exploit_commands=[
                    "# Extract all strings from APK",
                    "apktool d app.apk -o app_decoded",
                    "grep -r 'key\\|secret\\|token' app_decoded/smali/",
                ]
            ))

        return findings

    def _matches_key_value(self, s: str) -> bool:
        """Return True if the string looks like key material (base64, hex, or high-entropy)."""
        for pattern in self._KEY_VALUE_PATTERNS:
            if pattern.fullmatch(s):
                # Extra entropy check: require >50% unique characters
                if len(set(s)) > len(s) * 0.4:
                    return True
        return False


class InsecureRandomRule(BaseRule):
    """Detect use of insecure random number generators."""

    rule_id = "EXP-024"
    title = "Insecure Random Number Generator"
    severity = Severity.MEDIUM
    cwe = "CWE-338"
    description = "App uses java.util.Random instead of SecureRandom for security operations."

    def check(self) -> List[Finding]:
        """Check for insecure random usage."""
        findings = []

        if not self.callgraph:
            return findings

        random_methods = self.callgraph.search_methods("java/util/Random")
        math_random = self.callgraph.search_methods("Math;->random")

        seen_classes: set = set()
        for method in random_methods + math_random:
            class_name = dalvik_to_java(method)
            if not class_name or class_name in seen_classes:
                continue
            if self._is_third_party_component(class_name):
                continue
            seen_classes.add(class_name)

            findings.append(self.create_finding(
                component_name=class_name,
                confidence=Confidence.LIKELY,
                details={
                    "issue": "Insecure random generator used",
                    "method": method
                },
                code_snippet="Random random = new Random();  // Use SecureRandom instead",
                remediation="Replace java.util.Random with java.security.SecureRandom.",
                exploit_commands=[]
            ))

        return findings


class BrokenTrustManagerRule(BaseRule):
    """Detect custom X509TrustManager that accepts all certificates - CWE-295."""

    rule_id = "EXP-041"
    title = "Broken TrustManager (Accepts All Certificates)"
    severity = Severity.CRITICAL
    cwe = "CWE-295"
    description = (
        "App implements X509TrustManager with an empty checkServerTrusted() method, "
        "disabling certificate validation entirely. Any certificate — including self-signed "
        "or attacker-issued — is accepted, making HTTPS traffic trivially interceptable."
    )
    remediation = (
        "Remove the custom TrustManager. Use the default system TrustManager. "
        "If custom CA pinning is needed, use the Network Security Config file instead."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/295.html",
        "https://developer.android.com/training/articles/security-ssl",
    )

    def check(self) -> List[Finding]:
        findings = []

        if not self.callgraph:
            return findings

        seen: set = set()

        for sig in self.callgraph.search_methods("checkServerTrusted"):
            # Only look at the implementing method itself (name contains checkServerTrusted)
            if "checkServerTrusted" not in sig:
                continue
            if sig in seen:
                continue
            seen.add(sig)

            # Skip third-party SDK implementations
            class_name = dalvik_to_java(sig)
            if self._is_third_party_component(class_name):
                continue

            # Empty callees → method body makes no verification calls → accepts all certs
            callees = self.callgraph.get_callees(sig)
            throws_exception = any(
                "CertificateException" in c or "checkServerTrusted" in c
                for c in callees
            )
            if throws_exception:
                continue  # properly rejects or delegates — not vulnerable

            findings.append(self.create_finding(
                component_name=class_name or "Application",
                confidence=Confidence.LIKELY if not callees else Confidence.POSSIBLE,
                code_snippet=(
                    "// Dangerous — accepts every certificate:\n"
                    "public void checkServerTrusted(X509Certificate[] chain, String authType) {}\n\n"
                    "// Fix — remove this class and use the default TrustManager,\n"
                    "// or configure trusted CAs via Network Security Config."
                ),
                exploit_commands=[
                    "# Intercept HTTPS traffic with a self-signed certificate:",
                    "# 1. Set up mitmproxy or Burp Suite on the same network",
                    "mitmproxy --mode transparent --showhost",
                    "# 2. Route device traffic through the proxy (ARP spoof or WiFi AP)",
                    "# 3. All HTTPS connections from the app will succeed — no cert error",
                    "# Verify with Frida:",
                    "# frida -U -n com.target.app -e \"Java.use('javax.net.ssl.HttpsURLConnection')"
                    ".getDefaultSSLSocketFactory().method('createSocket').implementation = ...\"",
                ],
                exploit_scenario=(
                    f"{class_name} accepts any TLS certificate without validation. "
                    "An attacker on the same network (coffee shop, corporate WiFi) can "
                    "perform a MITM attack and read or modify all HTTPS traffic from this app."
                ),
                api_level_affected="All",
            ))

        return findings


class AllowAllHostnameVerifierRule(BaseRule):
    """Detect allow-all HostnameVerifier that skips hostname checking - CWE-297."""

    rule_id = "EXP-042"
    title = "Allow-All HostnameVerifier (Hostname Verification Disabled)"
    severity = Severity.HIGH
    cwe = "CWE-297"
    description = (
        "App installs a HostnameVerifier that accepts any hostname, or uses "
        "ALLOW_ALL_HOSTNAME_VERIFIER / allowAllHostnames(). "
        "An attacker with any valid certificate for any domain can intercept HTTPS traffic."
    )
    remediation = (
        "Remove the custom HostnameVerifier. The default verifier enforces hostname matching. "
        "Never use SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER in production."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/297.html",
        "https://developer.android.com/training/articles/security-ssl",
    )

    _ALLOW_ALL_PATTERNS = (
        "ALLOW_ALL_HOSTNAME_VERIFIER",
        "allowAllHostnames",
        "AllowAllHostnameVerifier",
        "NullHostnameVerifier",
    )

    def check(self) -> List[Finding]:
        findings = []

        if not self.callgraph:
            return findings

        seen: set = set()

        for pattern in self._ALLOW_ALL_PATTERNS:
            for sig in self.callgraph.search_methods(pattern):
                if sig in seen:
                    continue
                seen.add(sig)

                class_name = dalvik_to_java(sig)
                if self._is_third_party_component(class_name):
                    continue

                findings.append(self.create_finding(
                    component_name=class_name or "Application",
                    confidence=Confidence.CONFIRMED,
                    code_snippet=(
                        "// Dangerous — skips hostname verification entirely:\n"
                        "SSLSocketFactory.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);\n"
                        "// or: HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true);\n\n"
                        "// Fix — remove this; the default verifier enforces hostname matching."
                    ),
                    exploit_commands=[
                        "# With any valid TLS cert for ANY domain, intercept the connection:",
                        "# 1. Obtain a valid cert for attacker.com (e.g. Let's Encrypt)",
                        "# 2. Set up mitmproxy with that cert:",
                        "mitmproxy --certs *=attacker.com.pem --mode transparent",
                        "# 3. Route device traffic through the proxy",
                        "# The app will connect successfully — hostname is never checked",
                    ],
                    exploit_scenario=(
                        f"{class_name} disables hostname verification. "
                        "An attacker who can intercept network traffic only needs a valid "
                        "TLS certificate for any domain (e.g. a free Let's Encrypt cert) "
                        "to successfully MITM all HTTPS connections from this app."
                    ),
                    api_level_affected="All",
                ))

        return findings


class WebViewSslErrorIgnoredRule(BaseRule):
    """Detect WebView onReceivedSslError that calls handler.proceed() - CWE-295."""

    rule_id = "EXP-043"
    title = "WebView SSL Error Silently Ignored"
    severity = Severity.HIGH
    cwe = "CWE-295"
    description = (
        "WebViewClient.onReceivedSslError() calls handler.proceed(), silently accepting "
        "invalid or untrusted TLS certificates in the WebView. Any HTTPS page loaded in "
        "this WebView is vulnerable to MITM interception."
    )
    remediation = (
        "Call handler.cancel() instead of handler.proceed() in onReceivedSslError(). "
        "If a specific self-signed CA is required, add it via Network Security Config."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/295.html",
        "https://developer.android.com/reference/android/webkit/WebViewClient#onReceivedSslError",
    )

    def check(self) -> List[Finding]:
        findings = []

        if not self.callgraph:
            return findings

        seen: set = set()

        for sig in self.callgraph.search_methods("onReceivedSslError"):
            if "onReceivedSslError" not in sig:
                continue
            if sig in seen:
                continue
            seen.add(sig)

            class_name = dalvik_to_java(sig)
            if self._is_third_party_component(class_name):
                continue

            # Look for handler.proceed() in callees
            callees = self.callgraph.get_callees(sig)
            calls_proceed = any("proceed" in c for c in callees)
            calls_cancel = any("cancel" in c for c in callees)

            if calls_cancel and not calls_proceed:
                continue  # correctly rejects

            confidence = Confidence.CONFIRMED if calls_proceed else Confidence.LIKELY

            pkg = self.apk_parser.get_package_name()
            findings.append(self.create_finding(
                component_name=class_name or "Application",
                confidence=confidence,
                code_snippet=(
                    "// Dangerous — proceeds despite SSL error:\n"
                    "@Override\n"
                    "public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {\n"
                    "    handler.proceed();  // accepts invalid/self-signed/expired certs\n"
                    "}\n\n"
                    "// Fix:\n"
                    "handler.cancel();  // reject the connection"
                ),
                exploit_commands=[
                    "# Intercept WebView HTTPS traffic with an invalid/self-signed cert:",
                    "# 1. Set up mitmproxy on the same network",
                    "mitmproxy --mode transparent --showhost",
                    "# 2. Observe WebView traffic — SSL errors are silently accepted",
                    "# Confirm with Frida — hook onReceivedSslError to log error type:",
                    f"frida -U -n {pkg} -e \"Java.perform(function(){{",
                    "  var WVC = Java.use('android.webkit.WebViewClient');",
                    "  WVC.onReceivedSslError.implementation = function(view, handler, error) {",
                    "    console.log('SSL error: ' + error.toString());",
                    "    this.onReceivedSslError(view, handler, error);",
                    "  };",
                    "})\"",
                ],
                exploit_scenario=(
                    f"{class_name} calls handler.proceed() on SSL errors in WebView. "
                    "An attacker on the same network can serve any HTTPS page with an "
                    "invalid certificate and the WebView will load it without warning, "
                    "enabling full MITM of all WebView traffic."
                ),
                api_level_affected="All",
            ))

        return findings
