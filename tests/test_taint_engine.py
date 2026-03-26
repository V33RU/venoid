"""Tests for core.taint_engine."""

from unittest.mock import MagicMock, PropertyMock
from typing import List

import pytest

from core.taint_engine import TaintEngine, TaintPath, TaintStep


def _mock_method(class_name, name, descriptor="()V", is_external=False,
                 xref_to=None, full_name=None):
    """Create a mock MethodAnalysis."""
    m = MagicMock()
    m.class_name = class_name
    m.name = name
    m.descriptor = descriptor
    m.is_external.return_value = is_external
    m.full_name = full_name or f"{class_name} {name} {descriptor}"
    m.get_xref_to.return_value = xref_to or []
    return m


def _mock_xref(class_name, method_name, offset=0):
    """Create a mock xref tuple (class_obj, method_obj, offset)."""
    cls = MagicMock()
    cls.name = class_name
    method = MagicMock()
    method.name = method_name
    return (cls, method, offset)


class TestAppMethodFilter:
    def test_external_method_excluded(self):
        engine = TaintEngine([], MagicMock(), app_package="com.test.app")
        m = _mock_method("Lcom/test/app/Foo;", "bar", is_external=True)
        assert engine._is_app_method(m) is False

    def test_app_method_included(self):
        engine = TaintEngine([], MagicMock(), app_package="com.test.app")
        m = _mock_method("Lcom/test/app/Foo;", "bar", is_external=False)
        assert engine._is_app_method(m) is True

    def test_third_party_excluded(self):
        engine = TaintEngine([], MagicMock(), app_package="com.test.app")
        m = _mock_method("Landroidx/core/Foo;", "bar", is_external=False)
        assert engine._is_app_method(m) is False

    def test_empty_package_includes_all_non_external(self):
        engine = TaintEngine([], MagicMock(), app_package="")
        m = _mock_method("Lcom/random/Foo;", "bar", is_external=False)
        assert engine._is_app_method(m) is True


class TestCallsAny:
    def test_matches_callee(self):
        engine = TaintEngine([], MagicMock(), app_package="com.test")
        xrefs = [_mock_xref("Landroid/content/Intent;", "getStringExtra")]
        m = _mock_method("Lcom/test/Foo;", "onCreate", xref_to=xrefs)
        assert engine._calls_any(m, ["getStringExtra"]) is True

    def test_no_match(self):
        engine = TaintEngine([], MagicMock(), app_package="com.test")
        xrefs = [_mock_xref("Landroid/util/Log;", "d")]
        m = _mock_method("Lcom/test/Foo;", "onCreate", xref_to=xrefs)
        assert engine._calls_any(m, ["getStringExtra"]) is False


class TestFindSourcesSinks:
    def test_find_sources(self):
        source_method = _mock_method(
            "Lcom/test/app/Foo;", "handleIntent",
            xref_to=[_mock_xref("Landroid/app/Activity;", "getIntent")],
        )
        non_source = _mock_method(
            "Lcom/test/app/Bar;", "doStuff",
            xref_to=[_mock_xref("Landroid/util/Log;", "d")],
        )
        analysis = MagicMock()
        analysis.get_methods.return_value = [source_method, non_source]

        engine = TaintEngine([], analysis, app_package="com.test.app")
        sources = engine.find_sources()
        assert len(sources) == 1
        assert sources[0] is source_method

    def test_find_sinks(self):
        sink_method = _mock_method(
            "Lcom/test/app/WebAct;", "loadPage",
            xref_to=[_mock_xref("Landroid/webkit/WebView;", "loadUrl")],
        )
        analysis = MagicMock()
        analysis.get_methods.return_value = [sink_method]

        engine = TaintEngine([], analysis, app_package="com.test.app")
        sinks = engine.find_sinks()
        assert len(sinks) == 1
        assert sinks[0] is sink_method


class TestTrackTaint:
    def test_direct_source_to_sink(self):
        """Source method directly calls a sink method via xref."""
        sink = _mock_method(
            "Lcom/test/app/WebAct;", "loadPage",
            xref_to=[_mock_xref("Landroid/webkit/WebView;", "loadUrl")],
        )
        source = _mock_method(
            "Lcom/test/app/Main;", "onCreate",
            xref_to=[
                _mock_xref("Landroid/app/Activity;", "getIntent"),
                # xref_to also includes a reference to the sink method
                (MagicMock(name="cls"), sink, 0),
            ],
        )

        analysis = MagicMock()
        analysis.get_methods.return_value = [source, sink]

        engine = TaintEngine([], analysis, app_package="com.test.app")
        paths = engine.track_taint([source], [sink])
        assert len(paths) >= 1
        assert paths[0].confidence == "CONFIRMED"

    def test_max_depth_prevents_deep_traversal(self):
        """DFS should stop at max_depth."""
        analysis = MagicMock()
        engine = TaintEngine([], analysis, app_package="com.test.app")

        # Chain of 10 methods — sink at depth 10
        methods = []
        for i in range(10):
            methods.append(_mock_method(
                f"Lcom/test/app/C{i};", f"m{i}",
            ))
        # Wire up xref chain
        for i in range(9):
            methods[i].get_xref_to.return_value = [(MagicMock(), methods[i + 1], 0)]

        paths = engine.track_taint([methods[0]], [methods[9]], max_depth=3)
        assert len(paths) == 0  # sink is too deep


class TestGetPathsToSink:
    def test_filters_by_sink_api(self):
        engine = TaintEngine([], MagicMock(), app_package="com.test")
        engine.taint_paths = [
            TaintPath(source="A", sink="B", steps=[], sink_api="rawQuery"),
            TaintPath(source="C", sink="D", steps=[], sink_api="loadUrl"),
        ]
        result = engine.get_paths_to_sink("rawQuery")
        assert len(result) == 1
        assert result[0].sink_api == "rawQuery"

    def test_matches_sink_signature_too(self):
        engine = TaintEngine([], MagicMock(), app_package="com.test")
        engine.taint_paths = [
            TaintPath(source="A", sink="Lcom/test/Foo;->doRawQuery()V",
                      steps=[], sink_api=""),
        ]
        # "rawQuery" is a substring of "doRawQuery", so it should match via sink field
        result = engine.get_paths_to_sink("rawQuery")
        assert len(result) == 0  # lowercase "rawQuery" not in "doRawQuery" (case-sensitive)

        # "RawQuery" IS in "doRawQuery" — case-sensitive substring match
        result = engine.get_paths_to_sink("RawQuery")
        assert len(result) == 1

    def test_empty_paths(self):
        engine = TaintEngine([], MagicMock(), app_package="com.test")
        engine.taint_paths = []
        assert engine.get_paths_to_sink("loadUrl") == []
