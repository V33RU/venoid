"""Base rule class for all vulnerability detection rules."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum


class Severity(Enum):
    """Finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(Enum):
    """Finding confidence levels."""
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    POSSIBLE = "POSSIBLE"


@dataclass
class Finding:
    """Vulnerability finding dataclass."""
    rule_id: str
    component_type: str
    component_name: str
    severity: Severity
    confidence: Confidence
    cwe: str
    cvss_score: float
    title: str
    description: str
    code_snippet: str = ""
    taint_path: List[Dict[str, Any]] = field(default_factory=list)
    exploit_commands: List[str] = field(default_factory=list)
    exploit_scenario: str = ""
    remediation: str = ""
    api_level_affected: str = ""
    references: List[str] = field(default_factory=list)
    details: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        """Ensure all list fields are actual lists."""
        if not isinstance(self.taint_path, list):
            self.taint_path = []
        if not isinstance(self.exploit_commands, list):
            self.exploit_commands = []
        if not isinstance(self.references, list):
            self.references = []


class BaseRule(ABC):
    """Base class for all vulnerability detection rules."""

    rule_id: str = ""
    title: str = ""
    severity: Severity = Severity.MEDIUM
    cwe: str = ""
    description: str = ""
    remediation: str = ""
    references: List[str] = []
    component_type: str = ""   # set explicitly on each rule; fallback infers from class name

    # Common dangerous sinks shared by injection-detection rules
    DANGEROUS_SINKS: List[str] = [
        "exec(", "rawQuery", "execSQL", "loadUrl", "openFile",
        "sendBroadcast", "startActivity",
    ]

    # Known third-party SDK package prefixes — components from these are
    # legitimately exported by the SDK and should not be flagged as app bugs.
    THIRD_PARTY_PREFIXES: tuple = (
        "androidx.",
        "android.",
        "com.google.android.",
        "com.google.firebase.",
        "com.google.gms.",
        "com.facebook.",
        "com.bumptech.",
        "com.evernote.",
        "com.microsoft.",
        "com.huawei.",
        "com.appsflyer.",
        "com.adjust.",
        "com.braze.",
        "com.onesignal.",
        "com.mixpanel.",
        "com.amplitude.",
        "io.branch.",
        "okhttp3.",
        "retrofit2.",
        "io.reactivex.",
        "com.squareup.",
        "com.jakewharton.",
        "io.fabric.",
        "com.crashlytics.",
        "com.newrelic.",
        "com.datadog.",
    )

    def __init__(self, apk_parser: Any, callgraph: Any, taint_engine: Any) -> None:
        """Initialize rule with analysis components.

        Args:
            apk_parser: APK parser instance.
            callgraph: Callgraph instance.
            taint_engine: Taint engine instance.
        """
        self.apk_parser = apk_parser
        self.callgraph = callgraph
        self.taint_engine = taint_engine
        self.findings: List[Finding] = []

    @abstractmethod
    def check(self) -> List[Finding]:
        """Run the rule check.

        Returns:
            List of findings discovered by this rule.
        """
        pass

    def create_finding(
        self,
        component_name: str,
        confidence: Confidence,
        code_snippet: str = "",
        taint_path: Optional[List[Dict[str, Any]]] = None,
        exploit_commands: Optional[List[str]] = None,
        exploit_scenario: str = "",
        api_level_affected: str = "",
        details: Optional[Dict[str, Any]] = None,
        remediation: Optional[str] = None
    ) -> Finding:
        """Create a new finding with rule metadata.

        Args:
            component_name: Name of the vulnerable component.
            confidence: Confidence level of the finding.
            code_snippet: Decompiled code showing the issue.
            taint_path: Taint path from source to sink.
            exploit_commands: Ready-to-use exploit commands.
            exploit_scenario: Description of exploit scenario.
            api_level_affected: API levels affected.
            remediation: Additional remediation guidance (overrides default).
            details: Additional details about the finding.

        Returns:
            Finding object.
        """
        return Finding(
            rule_id=self.rule_id,
            component_type=self._get_component_type(),
            component_name=component_name,
            severity=self.severity,
            confidence=confidence,
            cwe=self.cwe,
            cvss_score=self._calculate_cvss(),
            title=self.title,
            description=self.description,
            code_snippet=code_snippet,
            taint_path=taint_path or [],
            exploit_commands=exploit_commands or [],
            exploit_scenario=exploit_scenario,
            remediation=remediation or self.remediation,
            api_level_affected=api_level_affected,
            references=self.references,
            details=details
        )

    def _get_component_type(self) -> str:
        """Get component type — uses explicit class attribute if set, otherwise infers from class name."""
        if self.component_type:
            return self.component_type
        class_name = self.__class__.__name__.lower()
        if "activity" in class_name:
            return "activity"
        elif "service" in class_name:
            return "service"
        elif "receiver" in class_name:
            return "receiver"
        elif "provider" in class_name:
            return "provider"
        elif "deeplink" in class_name:
            return "deeplink"
        return "unknown"

    def _calculate_cvss(self) -> float:
        """Calculate CVSS score based on severity.

        Returns:
            CVSS score (0-10).
        """
        scores = {
            Severity.CRITICAL: 9.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5,
            Severity.INFO: 0.0
        }
        return scores.get(self.severity, 5.0)

    @staticmethod
    def _safe_sdk_int(value: Any) -> int:
        """Safely convert an SDK version value to int."""
        try:
            return int(value) if value else 0
        except (ValueError, TypeError):
            return 0

    def _format_taint_path(self, path: Any) -> List[Dict[str, Any]]:
        """Convert a TaintPath object to a serialisable list of step dicts."""
        return [{"method": step.method, "instruction": step.instruction}
                for step in getattr(path, "steps", [])]

    def _get_manifest_app_element(self) -> Any:
        """Return the <application> element from the manifest, or None."""
        manifest = self.apk_parser.get_android_manifest_xml()
        if manifest is None:
            return None
        return manifest.find(".//application")

    def _is_third_party_component(self, component_name: str) -> bool:
        """Return True if the component belongs to a known third-party SDK.

        These components are intentionally exported by their SDK and flagging
        them as vulnerabilities produces false positives.
        """
        return component_name.startswith(self.THIRD_PARTY_PREFIXES)

    def _is_protected(self, permission: Optional[str]) -> bool:
        """Check if a permission provides adequate protection.

        Args:
            permission: Permission string.

        Returns:
            True if permission is signature/system level.
        """
        if not permission:
            return False

        protected_levels = ["signature", "signatureOrSystem", "system"]
        return any(level in permission.lower() for level in protected_levels)
