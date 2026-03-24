"""Vulnerability detection rules for Android components."""

from .base_rule import BaseRule, Finding, Severity, Confidence
from .activities import (
    ExportedActivityRule, IntentToWebViewRule, NestedIntentForwardingRule,
    TaskHijackingRule, TapjackingVulnerabilityRule, JavaScriptBridgeRule,
    WebViewFileAccessRule, IntentRedirectionRule,
)
from .services import ExportedServiceRule, ServiceIntentInjectionRule
from .receivers import ExportedReceiverRule, DynamicReceiverRule, ReceiverInjectionRule
from .providers import ExportedProviderRule, ProviderSQLInjectionRule, ProviderPathTraversalRule, GrantUriPermissionsRule, FileProviderBroadPathsRule
from .deeplinks import DeepLinkAutoVerifyRule, DeepLinkOpenRedirectRule, CustomSchemeHijackingRule
from .manifest_rules import (
    InsecureNetworkConfigRule, DebugModeEnabledRule,
    BackupEnabledRule, PendingIntentVulnerabilityRule
)
from .crypto_rules import HardcodedCryptoKeyRule, InsecureRandomRule

__all__ = [
    "BaseRule", "Finding", "Severity", "Confidence",
    # Activity rules
    "ExportedActivityRule", "IntentToWebViewRule", "NestedIntentForwardingRule",
    "TaskHijackingRule", "TapjackingVulnerabilityRule", "JavaScriptBridgeRule",
    "WebViewFileAccessRule", "IntentRedirectionRule",
    # Service rules
    "ExportedServiceRule", "ServiceIntentInjectionRule",
    # Receiver rules
    "ExportedReceiverRule", "DynamicReceiverRule", "ReceiverInjectionRule",
    # Provider rules
    "ExportedProviderRule", "ProviderSQLInjectionRule", "ProviderPathTraversalRule", "GrantUriPermissionsRule",
    "FileProviderBroadPathsRule",
    # Deep link rules
    "DeepLinkAutoVerifyRule", "DeepLinkOpenRedirectRule", "CustomSchemeHijackingRule",
    # Manifest/config rules
    "InsecureNetworkConfigRule", "DebugModeEnabledRule",
    "BackupEnabledRule", "PendingIntentVulnerabilityRule",
    # Crypto/code quality rules
    "HardcodedCryptoKeyRule", "InsecureRandomRule",
]
