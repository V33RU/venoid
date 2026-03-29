"""Tests for rules.base_rule."""

from unittest.mock import MagicMock

import pytest

from rules.base_rule import BaseRule, Finding, Severity, Confidence


class ConcreteRule(BaseRule):
    """Minimal concrete rule for testing base class behaviour."""
    rule_id = "TEST-001"
    title = "Test Rule"
    severity = Severity.HIGH
    cwe = "CWE-000"
    description = "Test description"
    remediation = "Test remediation"

    def check(self):
        return []


def _make_rule(**kwargs):
    return ConcreteRule(
        kwargs.get("apk_parser", MagicMock()),
        kwargs.get("callgraph", MagicMock()),
        kwargs.get("taint_engine", MagicMock()),
    )


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

class TestFinding:
    def test_post_init_fixes_bad_types(self):
        f = Finding(
            rule_id="X", component_type="a", component_name="b",
            severity=Severity.HIGH, confidence=Confidence.LIKELY,
            cwe="CWE-1", cvss_score=7.5, title="t", description="d",
            taint_path="not a list",  # type: ignore
            exploit_commands=None,  # type: ignore
            references=42,  # type: ignore
        )
        assert f.taint_path == []
        assert f.exploit_commands == []
        assert f.references == []

    def test_defaults(self):
        f = Finding(
            rule_id="X", component_type="a", component_name="b",
            severity=Severity.LOW, confidence=Confidence.POSSIBLE,
            cwe="CWE-1", cvss_score=2.5, title="t", description="d",
        )
        assert f.taint_path == []
        assert f.exploit_commands == []
        assert f.code_snippet == ""


# ---------------------------------------------------------------------------
# BaseRule
# ---------------------------------------------------------------------------

class TestBaseRule:
    def test_create_finding_populates_metadata(self):
        rule = _make_rule()
        finding = rule.create_finding(
            component_name="com.test.Foo",
            confidence=Confidence.CONFIRMED,
        )
        assert finding.rule_id == "TEST-001"
        assert finding.severity == Severity.HIGH
        assert finding.cwe == "CWE-000"
        assert finding.cvss_score == 7.5
        assert finding.component_name == "com.test.Foo"

    def test_calculate_cvss_scores(self):
        rule = _make_rule()
        for sev, expected in [
            (Severity.CRITICAL, 9.0),
            (Severity.HIGH, 7.5),
            (Severity.MEDIUM, 5.0),
            (Severity.LOW, 2.5),
            (Severity.INFO, 0.0),
        ]:
            rule.severity = sev
            assert rule._calculate_cvss() == expected

    def test_get_component_type_explicit(self):
        rule = _make_rule()
        rule.component_type = "provider"
        assert rule._get_component_type() == "provider"

    def test_get_component_type_inferred(self):
        rule = _make_rule()
        rule.component_type = ""
        # ConcreteRule has no keyword in name, so returns "unknown"
        assert rule._get_component_type() == "unknown"

    def test_is_third_party_component(self):
        rule = _make_rule()
        assert rule._is_third_party_component("androidx.core.SomeProvider") is True
        assert rule._is_third_party_component("com.google.firebase.FcmService") is True
        assert rule._is_third_party_component("com.myapp.MyActivity") is False

    def test_is_protected(self):
        rule = _make_rule()
        assert rule._is_protected(None) is False
        assert rule._is_protected("") is False
        assert rule._is_protected("android.permission.NORMAL") is False

        # Platform signature permissions should be protected
        assert rule._is_protected("android.permission.BIND_JOB_SERVICE") is True

        # Custom permission declared with signature protectionLevel
        rule.apk_parser.get_custom_permissions.return_value = [
            {"name": "com.test.MY_PERM", "protectionLevel": "signature"},
        ]
        assert rule._is_protected("com.test.MY_PERM") is True

        # Custom permission declared with normal protectionLevel
        rule.apk_parser.get_custom_permissions.return_value = [
            {"name": "com.test.WEAK_PERM", "protectionLevel": "normal"},
        ]
        assert rule._is_protected("com.test.WEAK_PERM") is False

        # Undeclared permission - not protected
        rule.apk_parser.get_custom_permissions.return_value = []
        assert rule._is_protected("com.test.UNKNOWN_PERM") is False

    def test_safe_sdk_int(self):
        assert BaseRule._safe_sdk_int("21") == 21
        assert BaseRule._safe_sdk_int(None) == 0
        assert BaseRule._safe_sdk_int("abc") == 0
        assert BaseRule._safe_sdk_int(33) == 33

    def test_mutable_defaults_not_shared(self):
        """Class-level references should be a tuple (immutable)."""
        assert isinstance(BaseRule.references, tuple)
        assert isinstance(BaseRule.DANGEROUS_SINKS, tuple)


class TestFormatTaintPath:
    def test_formats_steps(self):
        rule = _make_rule()
        path = MagicMock()
        step1 = MagicMock()
        step1.method = "Lcom/Foo;->bar()V"
        step1.instruction = "call"
        step2 = MagicMock()
        step2.method = "Lcom/Foo;->baz()V"
        step2.instruction = "sink"
        path.steps = [step1, step2]

        result = rule._format_taint_path(path)
        assert len(result) == 2
        assert result[0]["method"] == "Lcom/Foo;->bar()V"
        assert result[1]["instruction"] == "sink"

    def test_no_steps_attribute(self):
        rule = _make_rule()
        result = rule._format_taint_path("not a path object")
        assert result == []
