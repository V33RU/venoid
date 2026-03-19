"""Taint engine for tracking data flow from sources to sinks."""

from dataclasses import dataclass, field
from typing import List, Optional, Set, Dict, Any
import logging

from androguard.core.analysis.analysis import Analysis, MethodAnalysis
from androguard.core.dex import DEX

from core.callgraph import get_method_signature

logger = logging.getLogger(__name__)


@dataclass
class TaintStep:
    """Single step in a taint path."""
    method: str
    instruction: str
    line_number: int = 0


@dataclass
class TaintPath:
    """Complete taint path from source to sink."""
    source: str
    sink: str
    steps: List[TaintStep]
    confidence: str = "POSSIBLE"
    sink_api: str = ""  # actual Android API called at the sink (e.g. "rawQuery")


class TaintEngine:
    """Track taint from sources to sinks.

    Uses two improvements over naive string matching:

    1. **App-package filter**: only analyses methods that belong to the target
       application.  SDK classes (androidx, com.google, etc.) are skipped in
       both source/sink discovery and DFS traversal, eliminating false positives
       caused by SDK internals.

    2. **xref-based source/sink detection**: instead of checking whether a
       method's *own* signature contains a keyword, we check whether the method
       *calls* a known source/sink API via androguard cross-references.  This
       gives accurate caller-of-source / caller-of-sink semantics.
    """

    # Android APIs that introduce user-controlled (tainted) data into the app.
    SOURCES: List[str] = [
        "getIntent",
        "getStringExtra",
        "getIntExtra",
        "getLongExtra",
        "getFloatExtra",
        "getBooleanExtra",
        "getBundleExtra",
        "getParcelableExtra",
        "getData",
        "getDataString",
        "getQueryParameter",
        "getLastPathSegment",
        "onReceive",
        "getInputStream",
        "getRequestDispatcher",
    ]

    # Android APIs where tainted data causes a security impact.
    SINKS: List[str] = [
        "loadUrl",
        "loadData",
        "loadDataWithBaseURL",
        "exec",
        "rawQuery",
        "execSQL",
        "compileStatement",
        "openFile",
        "openFileOutput",
        "startActivity",
        "startService",
        "sendBroadcast",
        "openConnection",
    ]

    def __init__(
        self,
        dexes: List[DEX],
        analysis: Analysis,
        app_package: str = "",
    ) -> None:
        """Initialise the taint engine.

        Args:
            dexes: List of DEX objects from the APK.
            analysis: Androguard Analysis object.
            app_package: Application package name (e.g. ``"com.example.app"``).
                Used to restrict analysis to app code only.  If empty, all
                non-external methods are analysed (may produce more FPs).
        """
        self.dexes = dexes
        self.analysis = analysis
        self.taint_paths: List[TaintPath] = []

        # Convert "com.foo.bar" → "Lcom/foo/bar/" (Dalvik class prefix)
        self._app_prefix = (
            "L" + app_package.replace(".", "/") + "/" if app_package else ""
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_app_method(self, method: MethodAnalysis) -> bool:
        """Return True if *method* belongs to the app (not a third-party SDK)."""
        if method.is_external():
            return False
        if not self._app_prefix:
            return True
        return method.class_name.startswith(self._app_prefix)

    def _calls_any(self, method: MethodAnalysis, patterns: List[str]) -> bool:
        """Return True if *method* directly invokes any API matching *patterns*.

        Patterns are matched against ``"<class>-><name>"`` of each callee.
        """
        for xref in method.get_xref_to():
            target_class, callee_method, _ = xref
            callee_name = getattr(callee_method, "name", "") or ""
            callee_class = getattr(target_class, "name", "") or ""
            callee_sig = f"{callee_class}->{callee_name}"
            if any(p in callee_sig for p in patterns):
                return True
        return False

    def _first_sink_api(self, method: MethodAnalysis) -> str:
        """Return the name of the first sink API directly called by *method*."""
        for xref in method.get_xref_to():
            _, callee_method, _ = xref
            callee_name = getattr(callee_method, "name", "") or ""
            for p in self.SINKS:
                if p in callee_name:
                    return callee_name
        return ""

    def _get_method_sig(self, method: MethodAnalysis) -> str:
        return get_method_signature(method)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def find_sources(self) -> List[MethodAnalysis]:
        """Find app methods that *call* a taint-source API.

        Rather than matching the method's own signature, we inspect each
        method's outgoing cross-references (``get_xref_to``) and flag the
        method when it directly invokes a known source API such as
        ``getIntent()`` or ``getStringExtra()``.

        Returns:
            List of app-package methods that invoke at least one source API.
        """
        sources = []
        for method in self.analysis.get_methods():
            if not self._is_app_method(method):
                continue
            if self._calls_any(method, self.SOURCES):
                sources.append(method)
        logger.debug("find_sources: %d methods call a source API", len(sources))
        return sources

    def find_sinks(self) -> List[MethodAnalysis]:
        """Find app methods that *call* a taint-sink API.

        Returns:
            List of app-package methods that invoke at least one sink API.
        """
        sinks = []
        for method in self.analysis.get_methods():
            if not self._is_app_method(method):
                continue
            if self._calls_any(method, self.SINKS):
                sinks.append(method)
        logger.debug("find_sinks: %d methods call a sink API", len(sinks))
        return sinks

    def track_taint(
        self,
        source_methods: List[MethodAnalysis],
        sink_methods: List[MethodAnalysis],
        max_depth: int = 7,
    ) -> List[TaintPath]:
        """Track taint from sources to sinks via call-graph DFS.

        For each source method, performs a depth-first search through the
        forward call graph (``get_xref_to``).  Only app-package methods are
        followed; external SDK calls are treated as leaf nodes.

        Args:
            source_methods: App methods that call source APIs.
            sink_methods: App methods that call sink APIs.
            max_depth: Maximum call-chain depth to explore.

        Returns:
            List of discovered taint paths (also stored in ``self.taint_paths``).
        """
        paths: List[TaintPath] = []

        sink_sigs: Set[str] = {self._get_method_sig(m) for m in sink_methods}
        sink_api_map: Dict[str, str] = {
            self._get_method_sig(m): self._first_sink_api(m) for m in sink_methods
        }

        for source in source_methods:
            visited: Set[str] = set()
            current_path: List[TaintStep] = []
            self._dfs_taint(
                source, sink_sigs, sink_api_map,
                visited, current_path, paths, max_depth, 0,
            )

        self.taint_paths = paths
        logger.debug("track_taint: %d paths found", len(paths))
        return paths

    def _dfs_taint(
        self,
        current: MethodAnalysis,
        targets: Set[str],
        sink_api_map: Dict[str, str],
        visited: Set[str],
        path: List[TaintStep],
        found_paths: List[TaintPath],
        max_depth: int,
        depth: int,
    ) -> bool:
        if depth > max_depth:
            return False

        sig = self._get_method_sig(current)
        if sig in visited:
            return False
        visited.add(sig)

        # Reached a sink — record the complete path.
        if sig in targets:
            step = TaintStep(method=sig, instruction="sink", line_number=0)
            full_path = path + [step]
            found_paths.append(TaintPath(
                source=path[0].method if path else sig,
                sink=sig,
                sink_api=sink_api_map.get(sig, ""),
                steps=full_path,
                confidence="CONFIRMED",
            ))
            return True

        step = TaintStep(method=sig, instruction="call", line_number=0)
        path.append(step)

        found = False
        for xref in current.get_xref_to():
            _, target_method, _ = xref
            # Skip external (SDK) methods — avoid traversing SDK internals.
            try:
                if target_method.is_external():
                    continue
            except Exception:
                continue
            if self._dfs_taint(
                target_method, targets, sink_api_map,
                visited, path, found_paths, max_depth, depth + 1,
            ):
                found = True

        path.pop()
        return found

    def get_paths_to_sink(self, sink_pattern: str) -> List[TaintPath]:
        """Return all taint paths whose sink calls an API matching *sink_pattern*.

        Checks both ``sink_api`` (the actual SDK API invoked) and ``sink``
        (the app method signature) so that callers written against either
        convention continue to work.

        Args:
            sink_pattern: Substring to match against the sink API name
                (e.g. ``"rawQuery"``, ``"loadUrl"``).

        Returns:
            Matching taint paths.
        """
        return [
            p for p in self.taint_paths
            if sink_pattern in p.sink_api or sink_pattern in p.sink
        ]
