"""Rules for Android permission over-privilege analysis.

Two rules:
  EXP-056  UnusedDangerousPermissionRule    — declared dangerous perms with no API usage
  EXP-057  DangerousPermissionComboRule     — risky permission combinations
"""

from typing import Dict, List, Set, Tuple

from .base_rule import BaseRule, Finding, Severity, Confidence

# ── Dangerous permission → API method signature fragments ─────────────────────
# Each entry maps a permission to a tuple of Dalvik signature fragments whose
# presence in the call graph confirms the permission is actually used.
_PERM_TO_API: Dict[str, Tuple[str, ...]] = {
    "android.permission.READ_CONTACTS":       ("ContactsContract", "ContentResolver", "getContentResolver"),
    "android.permission.WRITE_CONTACTS":      ("ContactsContract", "ContentResolver", "getContentResolver"),
    "android.permission.READ_CALL_LOG":       ("CallLog", "getContentResolver"),
    "android.permission.WRITE_CALL_LOG":      ("CallLog", "getContentResolver"),
    "android.permission.READ_SMS":            ("Telephony/Sms", "SmsMessage", "getContentResolver"),
    "android.permission.SEND_SMS":            ("SmsManager", "sendTextMessage", "sendMultipartTextMessage"),
    "android.permission.RECEIVE_SMS":         ("SmsMessage", "android/provider/Telephony"),
    "android.permission.READ_PHONE_STATE":    ("TelephonyManager", "getDeviceId", "getImei", "getLine1Number"),
    "android.permission.CALL_PHONE":          ("Intent.ACTION_CALL", "tel:", "startActivity"),
    "android.permission.CAMERA":              ("android/hardware/Camera", "android/hardware/camera2", "CameraManager"),
    "android.permission.RECORD_AUDIO":        ("MediaRecorder", "AudioRecord", "startRecording"),
    "android.permission.ACCESS_FINE_LOCATION":("LocationManager", "FusedLocationProvider", "getLastKnownLocation", "requestLocationUpdates"),
    "android.permission.ACCESS_COARSE_LOCATION":("LocationManager", "getLastKnownLocation", "requestLocationUpdates"),
    "android.permission.READ_EXTERNAL_STORAGE":("Environment.getExternalStorage", "getExternalFilesDir", "openInputStream"),
    "android.permission.WRITE_EXTERNAL_STORAGE":("Environment.getExternalStorage", "getExternalFilesDir", "openOutputStream"),
    "android.permission.BLUETOOTH":           ("BluetoothAdapter", "BluetoothDevice", "BluetoothSocket"),
    "android.permission.BLUETOOTH_ADMIN":     ("BluetoothAdapter", "startDiscovery", "cancelDiscovery"),
    "android.permission.NFC":                 ("NfcAdapter", "NfcManager", "android/nfc"),
    "android.permission.BODY_SENSORS":        ("SensorManager", "TYPE_HEART_RATE", "TYPE_STEP_COUNTER"),
    "android.permission.PROCESS_OUTGOING_CALLS":("EXTRA_PHONE_NUMBER", "NEW_OUTGOING_CALL"),
    "android.permission.RECEIVE_MMS":         ("Mms", "Telephony/Mms"),
    "android.permission.USE_BIOMETRIC":       ("BiometricPrompt", "FingerprintManager"),
    "android.permission.USE_FINGERPRINT":     ("FingerprintManager", "BiometricPrompt"),
    "android.permission.GET_ACCOUNTS":        ("AccountManager", "getAccounts"),
    "android.permission.MANAGE_ACCOUNTS":     ("AccountManager",),
    "android.permission.USE_CREDENTIALS":     ("AccountManager", "getAuthToken"),
    "android.permission.READ_CALENDAR":       ("CalendarContract", "getContentResolver"),
    "android.permission.WRITE_CALENDAR":      ("CalendarContract", "getContentResolver"),
}

# ── Risky permission combinations ─────────────────────────────────────────────
# Each entry: (set_of_perms, title, risk_description)
_DANGEROUS_COMBOS: List[Tuple[Set[str], str, str]] = [
    (
        {"android.permission.CAMERA", "android.permission.INTERNET"},
        "Camera + Internet — Covert Surveillance Risk",
        "App can capture photos/video and upload them silently over the internet. "
        "Without a clear user-facing feature, this combination enables spyware behaviour.",
    ),
    (
        {"android.permission.RECORD_AUDIO", "android.permission.INTERNET"},
        "Microphone + Internet — Audio Exfiltration Risk",
        "App can record audio and transmit it. Combined with no visible UI for recording, "
        "this is a classic stalkerware pattern.",
    ),
    (
        {"android.permission.ACCESS_FINE_LOCATION", "android.permission.INTERNET"},
        "Fine Location + Internet — Persistent Tracking Risk",
        "App can report the device's precise GPS location to a remote server continuously. "
        "Ensure the user is clearly informed and has control over location sharing.",
    ),
    (
        {"android.permission.READ_SMS", "android.permission.INTERNET"},
        "Read SMS + Internet — OTP / 2FA Bypass Risk",
        "App can read all incoming SMS messages (including OTPs) and exfiltrate them. "
        "This is the mechanism used by banking malware and SIM-swap helpers.",
    ),
    (
        {"android.permission.READ_CONTACTS", "android.permission.INTERNET"},
        "Contacts + Internet — Contact Harvesting Risk",
        "App can upload the device address book to a remote server. "
        "Ensure data is anonymised and the user consents per GDPR/CCPA requirements.",
    ),
    (
        {
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.INTERNET",
            "android.permission.READ_SMS",
        },
        "Boot + SMS + Internet — Persistent Spyware Pattern",
        "App starts automatically on boot, reads SMS messages, and has internet access. "
        "This is the exact permission set used by SMS-stealing malware.",
    ),
    (
        {"android.permission.READ_PHONE_STATE", "android.permission.INTERNET"},
        "Device ID + Internet — Device Fingerprinting Risk",
        "App can obtain persistent device identifiers (IMEI, IMSI) and transmit them. "
        "This violates Play Store policy and may breach privacy regulations.",
    ),
    (
        {
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.INTERNET",
        },
        "Camera + Mic + Location + Internet — Full Surveillance Capability",
        "The app holds the full permission set required for covert device surveillance: "
        "video, audio, location, and exfiltration. This requires strong justification "
        "and transparent user consent flows.",
    ),
    (
        {"android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.READ_EXTERNAL_STORAGE"},
        "Full External Storage Access (Legacy)",
        "App requests unrestricted read+write to shared external storage. "
        "On Android 10+ this is deprecated; use scoped storage (MediaStore API). "
        "Overly broad storage access enables file-browsing and data theft.",
    ),
]


def _callgraph_has_any(callgraph, fragments: Tuple[str, ...]) -> bool:
    """Return True if the callgraph contains at least one method matching any fragment."""
    if callgraph is None:
        return False
    for frag in fragments:
        results = callgraph.search_methods(frag)
        if results:
            return True
    return False


# ── EXP-056: Unused Dangerous Permissions ─────────────────────────────────────

class UnusedDangerousPermissionRule(BaseRule):
    """Flag declared dangerous permissions that have no corresponding API usage in code."""

    rule_id        = "EXP-056"
    title          = "Declared Dangerous Permission Without Apparent API Usage"
    severity       = Severity.LOW
    cwe            = "CWE-272"
    component_type = "permissions"
    description    = (
        "The application declares one or more dangerous permissions in its manifest "
        "but no corresponding API calls were found in the DEX code. "
        "Unused permissions violate the principle of least privilege, bloat the "
        "permission dialog shown to users, and may cause Play Store policy violations."
    )
    remediation    = (
        "Remove any permission from AndroidManifest.xml that is not actively used "
        "by the application code. Audit each dangerous permission against an explicit "
        "feature requirement. Use the <uses-permission android:maxSdkVersion> attribute "
        "to limit permissions to the API levels that actually need them."
    )
    references     = (
        "https://developer.android.com/guide/topics/permissions/overview",
        "https://cwe.mitre.org/data/definitions/272.html",
        "https://owasp.org/www-project-mobile-top-10/2016-risks/m1-improper-platform-usage",
    )

    def check(self) -> List[Finding]:
        findings = []
        declared = set(self.apk_parser.get_permissions())

        for perm, api_fragments in _PERM_TO_API.items():
            if perm not in declared:
                continue
            if _callgraph_has_any(self.callgraph, api_fragments):
                continue   # permission appears to be used

            short = perm.replace("android.permission.", "")
            findings.append(self.create_finding(
                component_name=f"manifest::{short}",
                confidence=Confidence.POSSIBLE,
                exploit_scenario=(
                    f"{perm} is declared but no corresponding API usage was found. "
                    "This could indicate dead code, a dependency that uses the permission, "
                    "or a forgotten permission that was never cleaned up."
                ),
                details={
                    "permission":       perm,
                    "expected_api":     list(api_fragments[:4]),
                    "found_in_code":    False,
                },
                exploit_commands=[
                    f"# Verify manually — search smali for permission usage:",
                    f"apktool d target.apk && grep -r '{short}' target/smali/",
                    f"# Or with jadx:",
                    f"jadx -d out/ target.apk && grep -r '{short}' out/",
                ],
            ))

        return findings


# ── EXP-057: Dangerous Permission Combinations ────────────────────────────────

class DangerousPermissionComboRule(BaseRule):
    """Flag risky combinations of permissions that together enable privacy/security violations."""

    rule_id        = "EXP-057"
    title          = "Dangerous Permission Combination"
    severity       = Severity.HIGH
    cwe            = "CWE-250"
    component_type = "permissions"
    description    = (
        "The application declares a combination of permissions that together provide "
        "capabilities commonly associated with surveillance, data exfiltration, or "
        "privilege abuse. Individual permissions may be legitimate, but their "
        "combination warrants explicit review and user disclosure."
    )
    remediation    = (
        "For each flagged combination, document the exact feature that requires it "
        "and ensure clear, informed user consent is obtained before use. "
        "Apply runtime permission requests at the point of use (not at app start), "
        "provide rationale dialogs, and handle denials gracefully."
    )
    references     = (
        "https://developer.android.com/guide/topics/permissions/overview#dangerous_permissions",
        "https://cwe.mitre.org/data/definitions/250.html",
        "https://owasp.org/www-project-mobile-top-10/2016-risks/m1-improper-platform-usage",
    )

    def check(self) -> List[Finding]:
        findings = []
        declared = set(self.apk_parser.get_permissions())

        for combo_set, combo_title, combo_risk in _DANGEROUS_COMBOS:
            if not combo_set.issubset(declared):
                continue

            short_perms = [p.replace("android.permission.", "") for p in combo_set]
            findings.append(self.create_finding(
                component_name="manifest::permissions",
                confidence=Confidence.CONFIRMED,
                exploit_scenario=combo_risk,
                details={
                    "combination": sorted(short_perms),
                    "risk":        combo_risk,
                },
                exploit_commands=[
                    "# Inspect all declared permissions:",
                    "aapt dump permissions target.apk",
                    "# Or with apktool:",
                    "apktool d target.apk && grep 'uses-permission' target/AndroidManifest.xml",
                ],
                remediation=(
                    f"Justify the need for: {', '.join(sorted(short_perms))}. "
                    "Obtain granular runtime consent and consider removing permissions "
                    "not needed for the core user-facing feature."
                ),
            ))

        return findings
