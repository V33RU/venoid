"""Generate HTML security reports."""

from typing import List, Dict, Any
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from rules.base_rule import Finding, Severity


def _esc(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


SEV_COLOR = {
    "critical": "#ff4d4d",
    "high":     "#ff8c42",
    "medium":   "#ffd166",
    "low":      "#06d6a0",
    "info":     "#4da6ff",
}

SEV_GLOW = {
    "critical": "rgba(255,77,77,0.25)",
    "high":     "rgba(255,140,66,0.25)",
    "medium":   "rgba(255,209,102,0.20)",
    "low":      "rgba(6,214,160,0.20)",
    "info":     "rgba(77,166,255,0.20)",
}


def _badge(sev_lower: str) -> str:
    c = SEV_COLOR.get(sev_lower, "#888")
    return (
        f'<span style="background:{c}1a;color:{c};border:1px solid {c}55;'
        f'font-size:0.7em;font-weight:700;padding:2px 8px;border-radius:4px;'
        f'text-transform:uppercase;letter-spacing:.8px;vertical-align:middle;">'
        f'{sev_lower.upper()}</span>'
    )


def _render_instance(f: Dict[str, Any], sev_lower: str) -> str:
    color = SEV_COLOR.get(sev_lower, "#888")
    parts = [
        f'<details style="margin:6px 0 6px 24px;border-radius:6px;'
        f'border:1px solid #2a2a3a;background:#12121e;overflow:hidden;">',

        f'<summary style="cursor:pointer;padding:10px 14px;'
        f'display:flex;align-items:center;gap:10px;">'
        f'<span style="width:6px;height:6px;border-radius:50%;'
        f'background:{color};display:inline-block;flex-shrink:0;"></span>'
        f'<span style="font-weight:600;color:#e0e0f0;font-size:0.9em;flex:1;">'
        f'{_esc(f["component_name"])}</span>'
        f'<span style="font-size:0.75em;color:#555;margin-left:auto;'
        f'background:#1e1e30;padding:2px 8px;border-radius:10px;">'
        f'{_esc(f["confidence"].value)}</span>'
        f'</summary>',

        '<div style="padding:0 14px 12px 14px;border-top:1px solid #1e1e30;">',
    ]

    if f.get("code_snippet"):
        parts.append(
            f'<pre style="background:#0d0d1a;color:#a9b1d6;padding:12px 14px;'
            f'border-radius:6px;font-size:0.82em;overflow-x:auto;margin:10px 0;'
            f'border:1px solid #1e1e30;line-height:1.6;">'
            f'{_esc(f["code_snippet"])}</pre>'
        )

    if f.get("taint_path"):
        steps = ' <span style="color:#444;">→</span> '.join(
            f'<code style="color:#7aa2f7;background:#1a1a2e;padding:1px 5px;'
            f'border-radius:3px;font-size:0.82em;">'
            f'{_esc(s["method"] if isinstance(s, dict) else (s.method if hasattr(s, "method") else str(s)))}'
            f'</code>'
            for s in f["taint_path"]
        )
        parts.append(
            f'<div style="background:#0d0d1a;border:1px solid #1e1e30;'
            f'border-radius:6px;padding:8px 12px;margin:8px 0;font-size:0.83em;">'
            f'<span style="color:#555;font-size:0.85em;text-transform:uppercase;'
            f'letter-spacing:.5px;">Taint Path</span><br>'
            f'<span style="line-height:2;">{steps}</span></div>'
        )

    if f.get("exploit_commands"):
        parts.append(
            '<div style="background:#0d1117;border:1px solid #2a2a3a;'
            'border-radius:6px;padding:10px 14px;margin:8px 0;">'
            '<span style="color:#555;font-size:0.78em;text-transform:uppercase;'
            'letter-spacing:.5px;font-weight:600;">Attack Commands</span>'
        )
        for cmd in f["exploit_commands"]:
            if cmd.startswith("#"):
                parts.append(
                    f'<p style="color:#444;font-size:0.8em;font-family:monospace;'
                    f'margin:6px 0 2px 0;">{_esc(cmd)}</p>'
                )
            else:
                parts.append(
                    f'<pre style="background:#0a0a14;color:#50fa7b;padding:7px 12px;'
                    f'border-radius:4px;font-size:0.82em;margin:3px 0;'
                    f'border-left:2px solid #50fa7b44;">$ {_esc(cmd)}</pre>'
                )
        if f.get("exploit_scenario"):
            parts.append(
                f'<p style="font-size:0.82em;color:#666;margin:8px 0 0 0;'
                f'font-style:italic;line-height:1.5;">{_esc(f["exploit_scenario"])}</p>'
            )
        parts.append('</div>')

    parts.append('</div></details>')
    return "\n".join(parts)


def _render_group(title: str, instances: List[Dict[str, Any]]) -> str:
    f0 = instances[0]
    sev_lower = f0["severity"].value.lower()
    color = SEV_COLOR.get(sev_lower, "#888")
    glow  = SEV_GLOW.get(sev_lower, "transparent")
    count = len(instances)

    parts = [
        f'<details style="border:1px solid #1e1e30;border-left:3px solid {color};'
        f'border-radius:8px;margin-bottom:10px;background:#0f0f1a;overflow:hidden;">',

        f'<summary style="cursor:pointer;padding:12px 16px;'
        f'display:flex;align-items:center;gap:10px;">'
        f'{_badge(sev_lower)}'
        f'<span style="font-weight:600;color:#c9d1d9;font-size:0.93em;flex:1;">'
        f'{_esc(title)}</span>'
        f'<span style="background:{color}22;color:{color};border:1px solid {color}44;'
        f'font-size:0.75em;font-weight:700;padding:2px 10px;border-radius:10px;'
        f'flex-shrink:0;">{count}</span>'
        f'</summary>',

        f'<div style="padding:4px 16px 14px 16px;border-top:1px solid #1a1a2a;">',

        # Meta row
        f'<p style="font-size:0.78em;color:#444;margin:10px 0 8px 0;'
        f'font-family:monospace;letter-spacing:.3px;">'
        f'{_esc(f0["rule_id"])} &nbsp;·&nbsp; {_esc(f0["component_type"].upper())} '
        f'&nbsp;·&nbsp; {_esc(f0["cwe"])} &nbsp;·&nbsp; CVSS {f0["cvss_score"]}</p>',

        # Description
        f'<p style="font-size:0.88em;color:#8b949e;margin:0 0 8px 0;line-height:1.6;">'
        f'{_esc(f0["description"])}</p>',
    ]

    if f0.get("remediation"):
        parts.append(
            f'<div style="background:#0a1a12;border:1px solid #06d6a022;'
            f'border-radius:6px;padding:8px 12px;margin:8px 0;font-size:0.85em;">'
            f'<span style="color:#06d6a0;font-weight:600;">Fix &rarr;</span> '
            f'<span style="color:#6a9f7a;">{_esc(f0["remediation"])}</span>'
            f'</div>'
        )

    if f0.get("references"):
        links = " &nbsp;·&nbsp; ".join(
            f'<a href="{_esc(r)}" target="_blank" '
            f'style="color:#4da6ff;text-decoration:none;font-size:0.8em;">'
            f'{_esc(r.split("/")[-1] or r)}</a>'
            for r in f0["references"]
        )
        parts.append(f'<p style="margin:6px 0;color:#333;">{links}</p>')

    # Instances header
    parts.append(
        f'<div style="margin:12px 0 6px 0;font-size:0.78em;color:#444;'
        f'text-transform:uppercase;letter-spacing:.6px;font-weight:600;">'
        f'Affected components ({count})</div>'
    )

    for inst in instances:
        parts.append(_render_instance(inst, sev_lower))

    parts.append('</div></details>')
    return "\n".join(parts)


class HTMLReportGenerator:
    """Generate HTML security reports."""

    def __init__(self, package_name: str) -> None:
        self.package_name = package_name

    def generate(self, findings: List[Finding]) -> str:
        severity_order = {
            Severity.CRITICAL: 0, Severity.HIGH: 1,
            Severity.MEDIUM: 2,   Severity.LOW:  3, Severity.INFO: 4,
        }
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 5))

        counts: Dict[str, int] = {k: 0 for k in ("critical","high","medium","low","info")}
        for f in findings:
            counts[f.severity.value.lower()] += 1

        def to_dict(finding: Finding) -> Dict[str, Any]:
            return {
                "rule_id":            finding.rule_id,
                "component_type":     finding.component_type,
                "component_name":     finding.component_name,
                "severity":           finding.severity,
                "confidence":         finding.confidence,
                "cwe":                finding.cwe,
                "cvss_score":         finding.cvss_score,
                "title":              finding.title,
                "description":        finding.description,
                "code_snippet":       finding.code_snippet or "",
                "taint_path":         finding.taint_path or [],
                "exploit_commands":   finding.exploit_commands or [],
                "exploit_scenario":   finding.exploit_scenario or "",
                "remediation":        finding.remediation or "",
                "api_level_affected": finding.api_level_affected or "",
                "references":         finding.references or [],
                "details":            finding.details,
            }

        pkg       = _esc(self.package_name)
        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M")
        total     = len(findings)

        # Stat cards
        stat_cards = []
        for label, key, color in [
            ("Critical","critical","#ff4d4d"), ("High","high","#ff8c42"),
            ("Medium","medium","#ffd166"),     ("Low","low","#06d6a0"),
            ("Info","info","#4da6ff"),
        ]:
            n = counts[key]
            stat_cards.append(
                f'<div style="background:#0f0f1a;border:1px solid {color}33;'
                f'border-top:2px solid {color};border-radius:8px;'
                f'padding:14px 20px;min-width:100px;text-align:center;">'
                f'<div style="font-size:1.6em;font-weight:700;color:{color};">{n}</div>'
                f'<div style="font-size:0.75em;color:#555;text-transform:uppercase;'
                f'letter-spacing:.5px;margin-top:2px;">{label}</div>'
                f'</div>'
            )
        cards_html = "\n".join(stat_cards)

        # Build sections
        sections = []
        for label, sev_enum in [
            ("Critical", Severity.CRITICAL), ("High",   Severity.HIGH),
            ("Medium",   Severity.MEDIUM),   ("Low",    Severity.LOW),
            ("Info",     Severity.INFO),
        ]:
            bucket = [to_dict(f) for f in sorted_findings if f.severity == sev_enum]
            if not bucket:
                continue

            by_title: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
            for item in bucket:
                by_title[item["title"]].append(item)

            rendered = "\n".join(
                _render_group(t, insts) for t, insts in by_title.items()
            )
            n_types = len(by_title)
            n_total = len(bucket)
            color   = SEV_COLOR.get(label.lower(), "#888")
            sections.append(
                f'<div style="margin:28px 0 10px 0;display:flex;align-items:baseline;gap:10px;">'
                f'<span style="font-size:0.78em;font-weight:700;color:{color};'
                f'text-transform:uppercase;letter-spacing:1px;">{label}</span>'
                f'<span style="font-size:0.78em;color:#333;">'
                f'{n_types} type{"s" if n_types!=1 else ""}, '
                f'{n_total} instance{"s" if n_total!=1 else ""}</span>'
                f'<div style="flex:1;height:1px;background:#1a1a2a;margin-left:4px;"></div>'
                f'</div>\n{rendered}'
            )

        body = "\n".join(sections) if sections else \
            '<p style="color:#444;text-align:center;margin-top:60px;">No findings.</p>'

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ExPoser &mdash; {pkg}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Inter", sans-serif;
    background: #080810;
    color: #c9d1d9;
    line-height: 1.55;
    font-size: 14px;
    min-height: 100vh;
  }}
  .wrap {{ max-width: 920px; margin: 0 auto; padding: 40px 24px 60px; }}
  summary {{ list-style: none; }}
  summary::-webkit-details-marker {{ display: none; }}
  summary:hover {{ background: rgba(255,255,255,.03); }}
  a {{ color: #4da6ff; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  code {{
    background: #1a1a2e; color: #7aa2f7;
    padding: 1px 5px; border-radius: 3px; font-size: 0.88em;
  }}
  pre {{ white-space: pre-wrap; word-break: break-word; }}
  ::-webkit-scrollbar {{ width: 6px; height: 6px; background: #0d0d1a; }}
  ::-webkit-scrollbar-thumb {{ background: #2a2a3a; border-radius: 3px; }}
</style>
</head>
<body>
<div class="wrap">

  <!-- Header -->
  <div style="margin-bottom:32px;">
    <div style="font-size:0.75em;color:#444;text-transform:uppercase;
                letter-spacing:1.5px;margin-bottom:6px;">Android APK Security Report</div>
    <h1 style="font-size:1.5em;font-weight:700;color:#e0e0f0;letter-spacing:-.3px;">
      {pkg}
    </h1>
    <p style="color:#444;font-size:0.82em;margin-top:4px;">
      Scanned {scan_date} &nbsp;&bull;&nbsp; {total} finding{"s" if total != 1 else ""}
    </p>
  </div>

  <!-- Stat cards -->
  <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:36px;">
    {cards_html}
  </div>

  <!-- Findings -->
  {body}

  <!-- Footer -->
  <div style="margin-top:48px;padding-top:16px;border-top:1px solid #12121e;
              font-size:0.78em;color:#333;text-align:center;">
    Generated by <span style="color:#4da6ff;">ExPoser</span>
    &mdash; Android APK Security Analyzer
  </div>

</div>
</body>
</html>"""

    def save(self, findings: List[Finding], output_path: str) -> None:
        Path(output_path).write_text(self.generate(findings), encoding="utf-8")
