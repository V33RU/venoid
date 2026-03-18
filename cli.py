"""CLI interface for ExPoser using Click."""

import rich_click as click
import json
import logging

click.rich_click.USE_RICH_MARKUP = True
click.rich_click.USE_MARKDOWN = False
click.rich_click.SHOW_ARGUMENTS = True
click.rich_click.GROUP_ARGUMENTS_OPTIONS = False
click.rich_click.STYLE_COMMANDS_TABLE_SHOW_LINES = False
click.rich_click.STYLE_OPTIONS_DEFAULT_CURRENT = True
click.rich_click.MAX_WIDTH = 88
click.rich_click.OPTIONS_PANEL_TITLE = "Options"
click.rich_click.COMMAND_GROUPS = {
    "cli.py": [
        {
            "name": "Commands",
            "commands": ["scan"],
        }
    ]
}
import sys
from pathlib import Path
from typing import List, Optional
from collections import defaultdict

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich.rule import Rule
from rich.progress import (
    Progress, SpinnerColumn, BarColumn,
    TextColumn, TimeElapsedColumn, TaskProgressColumn
)

from core.apk_parser import APKParser
from core.callgraph import CallGraph
from core.taint_engine import TaintEngine

from rules.base_rule import Finding, Severity, Confidence
from rules.activities import (
    ExportedActivityRule, IntentToWebViewRule, NestedIntentForwardingRule,
    TaskHijackingRule, TapjackingVulnerabilityRule, JavaScriptBridgeRule
)
from rules.services import ExportedServiceRule, ServiceIntentInjectionRule
from rules.receivers import ExportedReceiverRule, DynamicReceiverRule, ReceiverInjectionRule
from rules.providers import ExportedProviderRule, ProviderSQLInjectionRule, ProviderPathTraversalRule, GrantUriPermissionsRule
from rules.deeplinks import DeepLinkAutoVerifyRule, DeepLinkOpenRedirectRule, CustomSchemeHijackingRule
from rules.manifest_rules import (
    InsecureNetworkConfigRule, DebugModeEnabledRule,
    BackupEnabledRule, PendingIntentVulnerabilityRule
)
from rules.crypto_rules import HardcodedCryptoKeyRule, InsecureRandomRule

from exploit.hint_generator import ExploitHintGenerator
from exploit.scenario_builder import ScenarioBuilder

from report.html_report import HTMLReportGenerator
from report.json_report import JSONReportGenerator
from report.sarif_report import SARIFReportGenerator

console = Console()

_SEV_COLOR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "orange3",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "green",
    Severity.INFO:     "blue",
}


def _silence_libs(verbose: bool) -> None:
    """Suppress noisy third-party loggers unless verbose."""
    level = logging.DEBUG if verbose else logging.WARNING

    # Standard logging — silence androguard and root
    logging.basicConfig(level=level,
                        format="%(levelname)s %(name)s: %(message)s",
                        handlers=[logging.StreamHandler()])
    for name in ("androguard", "androguard.core", "androguard.misc"):
        logging.getLogger(name).setLevel(logging.WARNING)

    # Androguard uses loguru in newer versions — disable it too
    try:
        from loguru import logger as _loguru
        if not verbose:
            _loguru.disable("androguard")
    except ImportError:
        pass


def get_all_rules(apk_parser, callgraph, taint_engine, components: Optional[str] = None) -> List:
    """Get rule instances, optionally filtered by component type."""
    active = {c.strip().lower() for c in components.split(',')} if components else None

    def include(t: str) -> bool:
        return active is None or t in active

    rules = []
    if include("activities"):
        rules += [
            ExportedActivityRule(apk_parser, callgraph, taint_engine),
            IntentToWebViewRule(apk_parser, callgraph, taint_engine),
            NestedIntentForwardingRule(apk_parser, callgraph, taint_engine),
            TaskHijackingRule(apk_parser, callgraph, taint_engine),
            TapjackingVulnerabilityRule(apk_parser, callgraph, taint_engine),
        ]
    if include("services"):
        rules += [
            ExportedServiceRule(apk_parser, callgraph, taint_engine),
            ServiceIntentInjectionRule(apk_parser, callgraph, taint_engine),
        ]
    if include("receivers"):
        rules += [
            ExportedReceiverRule(apk_parser, callgraph, taint_engine),
            DynamicReceiverRule(apk_parser, callgraph, taint_engine),
            ReceiverInjectionRule(apk_parser, callgraph, taint_engine),
        ]
    if include("providers"):
        rules += [
            ExportedProviderRule(apk_parser, callgraph, taint_engine),
            ProviderSQLInjectionRule(apk_parser, callgraph, taint_engine),
            ProviderPathTraversalRule(apk_parser, callgraph, taint_engine),
            GrantUriPermissionsRule(apk_parser, callgraph, taint_engine),
        ]
    if include("deeplinks"):
        rules += [
            DeepLinkAutoVerifyRule(apk_parser, callgraph, taint_engine),
            DeepLinkOpenRedirectRule(apk_parser, callgraph, taint_engine),
            CustomSchemeHijackingRule(apk_parser, callgraph, taint_engine),
        ]
    if active is None:
        rules += [
            InsecureNetworkConfigRule(apk_parser, callgraph, taint_engine),
            DebugModeEnabledRule(apk_parser, callgraph, taint_engine),
            BackupEnabledRule(apk_parser, callgraph, taint_engine),
            PendingIntentVulnerabilityRule(apk_parser, callgraph, taint_engine),
            HardcodedCryptoKeyRule(apk_parser, callgraph, taint_engine),
            InsecureRandomRule(apk_parser, callgraph, taint_engine),
        ]
    return rules


@click.group()
@click.version_option(version="1.0.0")
def cli() -> None:
    """ExPoser — Android APK Security Analyzer.

    Scans Android APK files for exported component vulnerabilities,
    taint flow issues, and generates exploit hints with ready-to-use
    ADB / Frida / drozer commands.

    \b
    Quick start:
      python3 cli.py scan app.apk
      python3 cli.py scan app.apk --help
    """
    pass


@cli.command()
@click.argument('apk_path', type=click.Path(exists=True, path_type=Path),
                metavar='APK_PATH')
@click.option('--output', '-o', multiple=True, default=['html'],
              type=click.Choice(['html', 'json', 'sarif'], case_sensitive=False),
              help='Report format(s). Repeatable: -o html -o json -o sarif  [default: html]')
@click.option('--severity', '-s', default='HIGH,CRITICAL',
              help='Comma-separated severity filter.  [default: HIGH,CRITICAL]',
              metavar='LEVELS')
@click.option('--min-confidence', '-c', default='LIKELY',
              type=click.Choice(['CONFIRMED', 'LIKELY', 'POSSIBLE'], case_sensitive=False),
              help='Minimum confidence to include.  [default: LIKELY]')
@click.option('--components', '-t', default=None,
              metavar='TYPES',
              help='Limit scan to component types (comma-separated).\n'
                   'Choices: activities, services, receivers, providers, deeplinks\n'
                   'Default: all')
@click.option('--exploit-hints', '-e', is_flag=True,
              help='Attach ADB / Frida / drozer commands to each finding.')
@click.option('--jadx-path', default='jadx',
              metavar='PATH',
              help='Path to jadx binary for source-level decompilation.  [default: jadx]')
@click.option('--output-dir', '-d', type=click.Path(path_type=Path), default=Path('.'),
              help='Directory to write report files.  [default: .]')
@click.option('--verbose', '-v', is_flag=True,
              help='Print full androguard + rule debug logs.')
def scan(
    apk_path: Path,
    output: tuple,
    severity: str,
    min_confidence: str,
    components: Optional[str],
    exploit_hints: bool,
    jadx_path: str,
    output_dir: Path,
    verbose: bool,
) -> None:
    """Scan an APK file for security vulnerabilities.

    \b
    Examples:
      python3 cli.py scan app.apk
      python3 cli.py scan app.apk -o html -o json -e -s CRITICAL,HIGH
      python3 cli.py scan app.apk -t activities,deeplinks -c POSSIBLE -d ./reports
    """
    _silence_libs(verbose)
    logger = logging.getLogger(__name__)

    severity_levels = [s.strip().upper() for s in severity.split(',')]
    min_conf_enum = Confidence[min_confidence.upper()]

    # ── Header ────────────────────────────────────────────────────────────────
    console.print()
    console.print(Panel(
        f"[bold white]ExPoser[/bold white] [dim]v1.0.0[/dim]  ·  Android APK Security Analyzer",
        border_style="bright_blue",
        padding=(0, 2),
    ))

    # ── 4-phase progress (transient — disappears when done) ────────────────────
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description:<30}"),
        BarColumn(bar_width=28),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )

    parser = None
    callgraph = None
    taint_engine = None
    all_findings: List[Finding] = []

    with progress:
        # Phase 1 — Load APK
        t1 = progress.add_task("Loading APK…", total=1)
        parser = APKParser(str(apk_path))
        if not parser.load():
            console.print("[red]✗ Failed to load APK[/red]")
            sys.exit(1)
        package_name = parser.get_package_name()
        progress.update(t1, completed=1, description="APK loaded")

        # Phase 2 — Build analysis engine
        t2 = progress.add_task("Building call graph…", total=1)
        if parser.analysis:
            callgraph = CallGraph(parser.dexes, parser.analysis)
            taint_engine = TaintEngine(parser.dexes, parser.analysis)
            sources = taint_engine.find_sources()
            sinks = taint_engine.find_sinks()
            taint_engine.track_taint(sources, sinks)
        progress.update(t2, completed=1, description="Call graph ready")

        # Phase 3 — Run rules
        rules = get_all_rules(parser, callgraph, taint_engine, components)
        t3 = progress.add_task("Running rules…", total=len(rules))
        for rule in rules:
            progress.update(t3, description=f"Rule {rule.rule_id}…")
            try:
                all_findings.extend(rule.check())
            except Exception as e:
                logger.debug(f"Rule {rule.rule_id} error: {e}")
            progress.advance(t3)
        progress.update(t3, description=f"{len(rules)} rules complete")

        # Phase 4 — Reports
        t4 = progress.add_task("Saving reports…", total=len(output))

        # Filter
        confidence_order = {Confidence.CONFIRMED: 0, Confidence.LIKELY: 1, Confidence.POSSIBLE: 2}
        min_conf_level = confidence_order.get(min_conf_enum, 3)
        filtered = [
            f for f in all_findings
            if f.severity.value in severity_levels
            and confidence_order.get(f.confidence, 3) <= min_conf_level
        ]

        # Exploit hints
        exploit_data = None
        scenario_data = None
        if exploit_hints and filtered:
            hint_gen = ExploitHintGenerator(package_name)
            exploit_data = hint_gen.generate_all_hints(filtered)
            scenario_data = ScenarioBuilder(package_name).build_all_scenarios(filtered)

        # Write reports
        saved: List[Path] = []
        output_dir.mkdir(parents=True, exist_ok=True)
        for fmt in output:
            out_file = output_dir / f"exposer_report_{package_name}.{fmt}"
            try:
                if fmt == 'html':
                    HTMLReportGenerator(package_name).save(filtered, str(out_file))
                elif fmt == 'json':
                    data = JSONReportGenerator(package_name).generate(filtered)
                    if exploit_data:
                        data['exploit_hints'] = exploit_data
                    if scenario_data:
                        data['scenarios'] = scenario_data
                    out_file.write_text(json.dumps(data, indent=2), encoding='utf-8')
                elif fmt == 'sarif':
                    SARIFReportGenerator(package_name).save(filtered, str(out_file))
                saved.append(out_file)
            except Exception as e:
                logger.error(f"Report {fmt} failed: {e}")
            progress.advance(t4)
        progress.update(t4, description="Reports saved")

    # ── Summary ───────────────────────────────────────────────────────────────
    console.print()

    # Counts per severity
    sev_counts: dict = defaultdict(int)
    sev_rules: dict = defaultdict(set)
    for f in filtered:
        sev_counts[f.severity] += 1
        sev_rules[f.severity].add(f.rule_id)

    # Left: target info
    info = Table.grid(padding=(0, 2))
    info.add_column(style="dim")
    info.add_column()
    info.add_row("Target",  f"[cyan]{apk_path.name}[/cyan]")
    info.add_row("Package", f"[cyan]{package_name}[/cyan]")
    info.add_row("Rules",   f"{len(rules)} checked")
    info.add_row("Scanned", f"{len(all_findings)} raw  →  [bold]{len(filtered)}[/bold] reported")

    # Right: severity breakdown
    sev_table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
    sev_table.add_column("Severity")
    sev_table.add_column("Count", justify="right")
    sev_table.add_column("Rules fired", style="dim")
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        n = sev_counts.get(sev, 0)
        if n == 0:
            continue
        color = _SEV_COLOR[sev]
        rules_hit = ", ".join(sorted(sev_rules[sev]))
        sev_table.add_row(
            Text(sev.value, style=color),
            Text(str(n), style=f"bold {color}"),
            rules_hit,
        )

    console.print(Panel(
        Columns([info, sev_table], equal=False, expand=True),
        title="[bold]Scan Results[/bold]",
        border_style="bright_blue",
        padding=(1, 2),
    ))

    # Saved reports
    if saved:
        console.print()
        console.print(Rule("[dim]Reports[/dim]", style="dim"))
        for path in saved:
            t = Text("  ✓ ", style="green")
            t.append(str(path), style=f"cyan link file://{path.resolve()}")
            console.print(t)

    # Critical warning
    critical_count = sev_counts.get(Severity.CRITICAL, 0)
    if critical_count:
        console.print()
        console.print(Panel(
            f"[bold red]{critical_count} CRITICAL vulnerabilit{'y' if critical_count == 1 else 'ies'} found — review immediately[/bold red]",
            border_style="red",
            padding=(0, 2),
        ))
        sys.exit(1)

    console.print()


if __name__ == '__main__':
    cli()
