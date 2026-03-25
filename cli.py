"""CLI interface for ExPoser using Click."""

import rich_click as click
import json
import logging
import subprocess
import platform

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
            "commands": ["scan", "rules"],
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
    TaskHijackingRule, TapjackingVulnerabilityRule, JavaScriptBridgeRule,
    FragmentInjectionRule, InsecureWebResourceResponseRule,
    WebViewFileAccessRule, IntentRedirectionRule,
)
from rules.services import ExportedServiceRule, ServiceIntentInjectionRule
from rules.receivers import ExportedReceiverRule, DynamicReceiverRule, ReceiverInjectionRule, UnprotectedSendBroadcastRule, StickyBroadcastRule
from rules.providers import (
    ExportedProviderRule, ProviderSQLInjectionRule, ProviderPathTraversalRule,
    GrantUriPermissionsRule, TypoPermissionRule, FileProviderBroadPathsRule,
)
from rules.deeplinks import DeepLinkAutoVerifyRule, DeepLinkOpenRedirectRule, CustomSchemeHijackingRule
from rules.manifest_rules import (
    InsecureNetworkConfigRule, DebugModeEnabledRule,
    BackupEnabledRule, PendingIntentVulnerabilityRule
)
from rules.crypto_rules import HardcodedCryptoKeyRule, InsecureRandomRule, BrokenTrustManagerRule, AllowAllHostnameVerifierRule, WebViewSslErrorIgnoredRule
from rules.storage_rules import InsecureLoggingRule, DynamicCodeLoadingRule, SecureScreenFlagRule

from exploit.hint_generator import ExploitHintGenerator
from exploit.scenario_builder import ScenarioBuilder
from exploit.frida_scripts import FridaScriptGenerator

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

# All rule classes with their category, used by both `scan` and `rules` commands
_ALL_RULE_CLASSES = [
    ("activities", ExportedActivityRule),
    ("activities", IntentToWebViewRule),
    ("activities", NestedIntentForwardingRule),
    ("activities", TaskHijackingRule),
    ("activities", TapjackingVulnerabilityRule),
    ("activities", JavaScriptBridgeRule),
    ("activities", FragmentInjectionRule),
    ("activities", InsecureWebResourceResponseRule),
    ("activities", WebViewFileAccessRule),
    ("activities", IntentRedirectionRule),
    ("services",   ExportedServiceRule),
    ("services",   ServiceIntentInjectionRule),
    ("receivers",  ExportedReceiverRule),
    ("receivers",  DynamicReceiverRule),
    ("receivers",  ReceiverInjectionRule),
    ("receivers",  UnprotectedSendBroadcastRule),
    ("receivers",  StickyBroadcastRule),
    ("providers",  ExportedProviderRule),
    ("providers",  ProviderSQLInjectionRule),
    ("providers",  ProviderPathTraversalRule),
    ("providers",  GrantUriPermissionsRule),
    ("providers",  TypoPermissionRule),
    ("providers",  FileProviderBroadPathsRule),
    ("deeplinks",  DeepLinkAutoVerifyRule),
    ("deeplinks",  DeepLinkOpenRedirectRule),
    ("deeplinks",  CustomSchemeHijackingRule),
    ("manifest",   InsecureNetworkConfigRule),
    ("manifest",   DebugModeEnabledRule),
    ("manifest",   BackupEnabledRule),
    ("manifest",   PendingIntentVulnerabilityRule),
    ("crypto",     HardcodedCryptoKeyRule),
    ("crypto",     InsecureRandomRule),
    ("crypto",     BrokenTrustManagerRule),
    ("crypto",     AllowAllHostnameVerifierRule),
    ("crypto",     WebViewSslErrorIgnoredRule),
    ("storage",    InsecureLoggingRule),
    ("storage",    DynamicCodeLoadingRule),
    ("storage",    SecureScreenFlagRule),
]


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


def _open_in_browser(path: Path) -> None:
    """Open a file in the default browser, cross-platform."""
    try:
        if platform.system() == "Darwin":
            subprocess.Popen(["open", str(path)])
        elif platform.system() == "Windows":
            subprocess.Popen(["start", str(path)], shell=True)
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except Exception:
        pass


def get_all_rules(apk_parser, callgraph, taint_engine, components: Optional[str] = None) -> List:
    """Get rule instances, optionally filtered by component type."""
    active = {c.strip().lower() for c in components.split(',')} if components else None

    # manifest/crypto/storage rules always run when no filter is set
    always_run = {"manifest", "crypto", "storage"}

    rules = []
    for category, cls in _ALL_RULE_CLASSES:
        if active is None:
            rules.append(cls(apk_parser, callgraph, taint_engine))
        elif category in active:
            rules.append(cls(apk_parser, callgraph, taint_engine))
        elif category in always_run and active.isdisjoint(always_run):
            # only include always-run categories when no component filter touches them
            rules.append(cls(apk_parser, callgraph, taint_engine))
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
      python3 cli.py rules
    """
    pass


@cli.command(name="rules")
@click.option('--category', '-c', default=None,
              help='Filter by category (activities, services, receivers, providers, deeplinks, manifest, crypto, storage).')
def list_rules(category: Optional[str]) -> None:
    """List all available detection rules.

    \b
    Examples:
      python3 cli.py rules
      python3 cli.py rules --category deeplinks
    """
    console.print()
    console.print(Panel(
        "[bold white]ExPoser[/bold white] [dim]v1.0.0[/dim]  ·  Available Detection Rules",
        border_style="bright_blue",
        padding=(0, 2),
    ))
    console.print()

    table = Table(show_header=True, header_style="bold dim", border_style="dim", padding=(0, 1))
    table.add_column("ID",       style="cyan",    no_wrap=True, width=10)
    table.add_column("Severity", no_wrap=True,    width=10)
    table.add_column("Category", style="dim",     width=12)
    table.add_column("CWE",      style="dim",     width=10)
    table.add_column("Title",    no_wrap=False)

    cat_filter = category.lower() if category else None
    count = 0
    for cat, cls in _ALL_RULE_CLASSES:
        if cat_filter and cat != cat_filter:
            continue
        sev = cls.severity
        color = _SEV_COLOR.get(sev, "white")
        table.add_row(
            cls.rule_id,
            Text(sev.value, style=color),
            cat,
            cls.cwe,
            cls.title,
        )
        count += 1

    console.print(table)
    console.print()
    console.print(f"[dim]{count} rule(s) shown.  Run [cyan]python3 cli.py scan app.apk[/cyan] to use them.[/dim]")
    console.print()


@cli.command()
@click.argument('apk_path', type=click.Path(exists=True, path_type=Path),
                metavar='APK_PATH')
@click.option('--output', '-o', multiple=True, default=['html'],
              type=click.Choice(['html', 'json', 'sarif'], case_sensitive=False),
              help='Report format(s). Repeatable: -o html -o json -o sarif  [default: html]')
@click.option('--severity', '-s', default='MEDIUM,HIGH,CRITICAL',
              help='Comma-separated severity filter.  [default: MEDIUM,HIGH,CRITICAL]',
              metavar='LEVELS')
@click.option('--all', '-a', 'scan_all', is_flag=True,
              help='Show all findings (overrides --severity and --min-confidence).')
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
@click.option('--open', '-O', 'open_report', is_flag=True,
              help='Auto-open the HTML report in browser after scan.')
@click.option('--show-findings', '-f', is_flag=True,
              help='Print a findings table directly in the terminal.')
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
    scan_all: bool,
    min_confidence: str,
    components: Optional[str],
    exploit_hints: bool,
    open_report: bool,
    show_findings: bool,
    jadx_path: str,
    output_dir: Path,
    verbose: bool,
) -> None:
    """Scan an APK file for security vulnerabilities.

    \b
    Examples:
      python3 cli.py scan app.apk
      python3 cli.py scan app.apk --all --open
      python3 cli.py scan app.apk -o html -o json -e -s CRITICAL,HIGH
      python3 cli.py scan app.apk -t activities,deeplinks -c POSSIBLE -d ./reports
      python3 cli.py scan app.apk --show-findings
    """
    _silence_libs(verbose)
    logger = logging.getLogger(__name__)

    # --all overrides severity and confidence filters
    if scan_all:
        severity_levels = [s.value for s in Severity]
        min_conf_enum = Confidence.POSSIBLE
    else:
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
    written_scripts: List[Path] = []

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
            taint_engine = TaintEngine(parser.dexes, parser.analysis, app_package=package_name)
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
                logger.warning(f"Rule {rule.rule_id} failed: {e}", exc_info=verbose)
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

        # Exploit hints + Frida scripts
        exploit_data = None
        scenario_data = None
        if exploit_hints and filtered:
            hint_gen = ExploitHintGenerator(package_name)
            exploit_data = hint_gen.generate_all_hints(filtered)
            scenario_data = ScenarioBuilder(package_name).build_all_scenarios(filtered)

            # Write one .js file per finding into output_dir/frida/
            frida_gen = FridaScriptGenerator(package_name)
            frida_dir = output_dir / "frida"
            frida_dir.mkdir(parents=True, exist_ok=True)
            seen_scripts: set = set()
            for finding in filtered:
                short = finding.component_name.replace("/", ".").split(".")[-1].replace(";", "")[:40]
                js_name = f"{finding.rule_id}_{short}.js"
                if js_name in seen_scripts:
                    continue
                seen_scripts.add(js_name)
                js_path = frida_dir / js_name
                js_path.write_text(frida_gen.generate(finding), encoding="utf-8")
                written_scripts.append(js_path)

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

    # ── Hidden findings warning ────────────────────────────────────────────────
    hidden = len(all_findings) - len(filtered)
    if hidden > 0 and not scan_all:
        hidden_sevs = sorted({
            f.severity.value for f in all_findings
            if f.severity.value not in severity_levels
        })
        hint = ", ".join(hidden_sevs) if hidden_sevs else "lower severity"
        console.print(
            f"\n[yellow]⚠  {hidden} finding(s) hidden by current filters "
            f"({hint}).  Run with [bold]-a[/bold] / [bold]--all[/bold] to see everything.[/yellow]"
        )

    # ── No findings message ────────────────────────────────────────────────────
    if len(filtered) == 0:
        console.print()
        console.print("[dim]  No findings matched the current filters.[/dim]")
        if hidden > 0:
            console.print(f"[dim]  Tip: try [cyan]--all[/cyan] to bypass severity and confidence filters.[/dim]")

    # ── Inline findings table ──────────────────────────────────────────────────
    if show_findings and filtered:
        console.print()
        console.print(Rule("[dim]Findings[/dim]", style="dim"))
        ftable = Table(show_header=True, header_style="bold dim",
                       border_style="dim", padding=(0, 1), expand=True)
        ftable.add_column("Severity",   no_wrap=True, width=10)
        ftable.add_column("Confidence", no_wrap=True, width=11)
        ftable.add_column("Rule",       no_wrap=True, width=10)
        ftable.add_column("Component",  no_wrap=False)
        ftable.add_column("Title",      no_wrap=False)
        for f in sorted(filtered,
                        key=lambda x: list(Severity).index(x.severity)):
            color = _SEV_COLOR.get(f.severity, "white")
            ftable.add_row(
                Text(f.severity.value, style=color),
                Text(f.confidence.value, style="dim"),
                f.rule_id,
                f.component_name.split('.')[-1],   # short name for readability
                f.title,
            )
        console.print(ftable)

    # ── Saved reports ──────────────────────────────────────────────────────────
    if saved:
        console.print()
        console.print(Rule("[dim]Reports[/dim]", style="dim"))
        for path in saved:
            t = Text("  ✓ ", style="green")
            t.append(str(path), style=f"cyan link file://{path.resolve()}")
            console.print(t)

    # ── Frida scripts ──────────────────────────────────────────────────────────
    if exploit_hints and filtered and written_scripts:
        console.print()
        console.print(Rule("[dim]Frida Scripts[/dim]", style="dim"))
        for js_path in written_scripts:
            t = Text("  ✓ ", style="green")
            t.append(str(js_path), style=f"cyan link file://{js_path.resolve()}")
            console.print(t)
        pkg_hint = package_name
        console.print(
            f"\n[dim]  Run: [cyan]frida -U -n {pkg_hint} -s <script>.js[/cyan][/dim]"
        )

    # ── Auto-open HTML report ──────────────────────────────────────────────────
    if open_report:
        for path in saved:
            if str(path).endswith('.html'):
                _open_in_browser(path)
                console.print(f"[dim]  Opened {path.name} in browser.[/dim]")

    # ── Critical warning ───────────────────────────────────────────────────────
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
