"""Tests for core.apk_parser."""

import xml.etree.ElementTree as ET
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from core.apk_parser import APKParser, ANDROID_NS


NS = f"{{{ANDROID_NS}}}"


def _make_manifest(*components):
    """Build a minimal AndroidManifest.xml ElementTree from component tuples.

    Each component is (tag, name, exported, permission, intent_filters_xml).
    """
    root = ET.Element("manifest")
    app = ET.SubElement(root, "application")
    for tag, name, exported, permission, filters_xml in components:
        attrs = {f"{NS}name": name}
        if exported is not None:
            attrs[f"{NS}exported"] = str(exported).lower()
        if permission:
            attrs[f"{NS}permission"] = permission
        elem = ET.SubElement(app, tag, attrs)
        if filters_xml:
            for fxml in filters_xml:
                elem.append(ET.fromstring(fxml))
    return root


def _parser_with_manifest(manifest_xml, activities=None, services=None,
                           receivers=None, providers=None):
    """Create an APKParser with a mocked APK returning the given manifest."""
    parser = APKParser.__new__(APKParser)
    parser.apk_path = "fake.apk"
    parser.dexes = []
    parser.analysis = None
    parser._manifest_xml = manifest_xml

    apk = MagicMock()
    apk.get_android_manifest_xml.return_value = manifest_xml
    apk.get_activities.return_value = activities or []
    apk.get_services.return_value = services or []
    apk.get_receivers.return_value = receivers or []
    apk.get_providers.return_value = providers or []
    apk.get_package.return_value = "com.test.app"
    apk.get_min_sdk_version.return_value = "21"
    apk.get_target_sdk_version.return_value = "33"
    apk.get_permissions.return_value = []
    parser.apk = apk
    return parser


# ---------------------------------------------------------------------------
# get_min_sdk / get_target_sdk return int
# ---------------------------------------------------------------------------

class TestSDKVersions:
    def test_get_min_sdk_returns_int(self):
        parser = _parser_with_manifest(ET.Element("manifest"))
        assert parser.get_min_sdk() == 21
        assert isinstance(parser.get_min_sdk(), int)

    def test_get_target_sdk_returns_int(self):
        parser = _parser_with_manifest(ET.Element("manifest"))
        assert parser.get_target_sdk() == 33
        assert isinstance(parser.get_target_sdk(), int)

    def test_get_min_sdk_handles_none(self):
        parser = _parser_with_manifest(ET.Element("manifest"))
        parser.apk.get_min_sdk_version.return_value = None
        assert parser.get_min_sdk() == 0

    def test_get_target_sdk_handles_garbage(self):
        parser = _parser_with_manifest(ET.Element("manifest"))
        parser.apk.get_target_sdk_version.return_value = "not_a_number"
        assert parser.get_target_sdk() == 0

    def test_no_apk_returns_zero(self):
        parser = APKParser.__new__(APKParser)
        parser.apk = None
        assert parser.get_min_sdk() == 0
        assert parser.get_target_sdk() == 0


# ---------------------------------------------------------------------------
# get_manifest_element — strict matching
# ---------------------------------------------------------------------------

class TestManifestElementMatching:
    def test_exact_name_match(self):
        xml = _make_manifest(
            ("activity", "com.test.app.MainActivity", "true", None, None),
        )
        parser = _parser_with_manifest(xml)
        result = parser.get_manifest_element("activity", "exported", "com.test.app.MainActivity")
        assert result == "true"

    def test_short_name_does_not_match_unrelated(self):
        """Two activities with the same short name but different packages.
        Querying by full name should NOT match the wrong one."""
        xml = _make_manifest(
            ("activity", "com.foo.MainActivity", "true", None, None),
            ("activity", "com.bar.MainActivity", "false", None, None),
        )
        parser = _parser_with_manifest(xml)
        # Should find the first match (com.foo) when querying with exact name
        result = parser.get_manifest_element("activity", "exported", "com.foo.MainActivity")
        assert result == "true"

    def test_dotted_short_name_matches(self):
        """Short name prefixed with dot (e.g. .MainActivity) should match."""
        xml = _make_manifest(
            ("activity", ".MainActivity", None, None, None),
        )
        parser = _parser_with_manifest(xml)
        result = parser.get_manifest_element("activity", "name", "com.test.MainActivity")
        assert result == ".MainActivity"

    def test_no_match_returns_none(self):
        xml = _make_manifest(
            ("activity", "com.test.app.Other", "true", None, None),
        )
        parser = _parser_with_manifest(xml)
        result = parser.get_manifest_element("activity", "exported", "com.test.app.Missing")
        assert result is None


# ---------------------------------------------------------------------------
# _is_exported
# ---------------------------------------------------------------------------

class TestIsExported:
    def test_explicit_true(self):
        xml = _make_manifest(
            ("activity", "com.test.Foo", "true", None, None),
        )
        parser = _parser_with_manifest(xml, activities=["com.test.Foo"])
        assert parser._is_exported("activity", "com.test.Foo") is True

    def test_explicit_false(self):
        xml = _make_manifest(
            ("activity", "com.test.Foo", "false", None, None),
        )
        parser = _parser_with_manifest(xml, activities=["com.test.Foo"])
        assert parser._is_exported("activity", "com.test.Foo") is False

    def test_auto_exported_with_intent_filter(self):
        """Component with intent-filter but no explicit exported attr is auto-exported."""
        intent_filter = (
            f'<intent-filter><action {NS}name="android.intent.action.VIEW"/></intent-filter>'
        )
        xml = _make_manifest(
            ("activity", "com.test.Foo", None, None, [intent_filter]),
        )
        parser = _parser_with_manifest(xml, activities=["com.test.Foo"])
        assert parser._is_exported("activity", "com.test.Foo") is True


# ---------------------------------------------------------------------------
# _get_components (deduplication)
# ---------------------------------------------------------------------------

class TestGetComponents:
    def test_get_activities_returns_list(self):
        xml = _make_manifest(
            ("activity", "com.test.Main", "true", None, None),
        )
        parser = _parser_with_manifest(xml, activities=["com.test.Main"])
        result = parser.get_activities()
        assert len(result) == 1
        assert result[0]["name"] == "com.test.Main"
        assert result[0]["exported"] is True

    def test_get_services_returns_list(self):
        xml = _make_manifest(
            ("service", "com.test.MyService", "false", None, None),
        )
        parser = _parser_with_manifest(xml, services=["com.test.MyService"])
        result = parser.get_services()
        assert len(result) == 1
        assert result[0]["name"] == "com.test.MyService"

    def test_get_providers_includes_authorities(self):
        xml = _make_manifest(
            ("provider", "com.test.MyProvider", "true", None, None),
        )
        # Mock authorities
        parser = _parser_with_manifest(xml, providers=["com.test.MyProvider"])
        # authorities comes from a separate lookup, which returns None here
        result = parser.get_providers()
        assert len(result) == 1
        assert "authorities" in result[0]
