"""Generate SARIF 2.1.0 security reports."""

import json
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime, timezone
import hashlib

from rules.base_rule import Finding, Severity, Confidence


class SARIFReportGenerator:
    """Generate SARIF 2.1.0 security reports."""

    # Map our severity to SARIF level
    SEVERITY_TO_LEVEL = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "none"
    }

    def __init__(self, package_name: str, app_name: str = "") -> None:
        """Initialize report generator.

        Args:
            package_name: Target package name.
            app_name: Application name.
        """
        self.package_name = package_name
        self.app_name = app_name

    def generate(self, findings: List[Finding]) -> Dict[str, Any]:
        """Generate SARIF report structure.

        Args:
            findings: List of vulnerability findings.

        Returns:
            SARIF report dictionary.
        """
        # Build ordered rules list and index map
        rule_index_map: Dict[str, int] = {}
        rule_list = []
        for finding in findings:
            if finding.rule_id not in rule_index_map:
                rule_index_map[finding.rule_id] = len(rule_list)
                rule_list.append(self._create_rule(finding))

        # Build results
        results = []
        for finding in findings:
            result = self._create_result(finding, rule_index_map)
            if result:
                results.append(result)

        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        sarif_report = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "ExPoser",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/exposer/exposer",
                        "rules": rule_list
                    }
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": True,
                    "startTimeUtc": now_utc,
                    "endTimeUtc": now_utc
                }],
                "properties": {
                    "packageName": self.package_name,
                    "appName": self.app_name
                }
            }]
        }

        return sarif_report

    def _create_rule(self, finding: Finding) -> Dict[str, Any]:
        """Create SARIF rule definition from finding."""
        rule = {
            "id": finding.rule_id,
            "name": finding.title,
            "shortDescription": {
                "text": finding.title
            },
            "fullDescription": {
                "text": finding.description
            },
            "defaultConfiguration": {
                "level": self.SEVERITY_TO_LEVEL.get(finding.severity, "warning")
            },
            "properties": {
                "cwe": finding.cwe,
                "cvss": finding.cvss_score,
                "precision": finding.confidence.value.lower(),
                "tags": [finding.component_type, finding.cwe]
            }
        }

        # Add help text with remediation
        if finding.remediation:
            rule["help"] = {
                "text": finding.remediation,
                "markdown": f"**Remediation:**\n\n{finding.remediation}"
            }

        return rule

    def _create_result(self, finding: Finding, rule_index_map: Dict[str, int]) -> Optional[Dict[str, Any]]:
        """Create SARIF result from finding."""
        # Generate fingerprint
        fingerprint_data = f"{finding.rule_id}:{finding.component_name}:{finding.title}"
        fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]

        result = {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index_map.get(finding.rule_id, 0),
            "level": self.SEVERITY_TO_LEVEL.get(finding.severity, "warning"),
            "message": {
                "text": f"{finding.title}: {finding.description}"
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f"AndroidManifest.xml",
                        "uriBaseId": "SRCROOT"
                    },
                    "region": {
                        "startLine": 1,
                        "startColumn": 1,
                        "snippet": {
                            "text": finding.code_snippet if finding.code_snippet else f"<{finding.component_name} android:exported=\"true\" ... />"
                        }
                    }
                },
                "logicalLocations": [{
                    "name": finding.component_name,
                    "kind": finding.component_type
                }]
            }],
            "fingerprints": {
                "primary": fingerprint
            },
            "properties": {
                "confidence": finding.confidence.value,
                "componentType": finding.component_type,
                "cwe": finding.cwe,
                "cvss": finding.cvss_score
            }
        }

        # Add code flows for taint paths — all steps in a single flow
        if finding.taint_path:
            locations = [
                {
                    "location": {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "decompiled_source.java"},
                            "region": {"startLine": step.get("line_number", 1)}
                        },
                        "message": {"text": step.get("method", "unknown")}
                    }
                }
                for step in finding.taint_path
            ]
            result["codeFlows"] = [{"threadFlows": [{"locations": locations}]}]

        # Add related locations for exploit commands
        if finding.exploit_commands:
            related_locations = []
            for i, cmd in enumerate(finding.exploit_commands):
                related_locations.append({
                    "id": i,
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "exploit_commands.txt"
                        },
                        "region": {
                            "startLine": i + 1,
                            "snippet": {
                                "text": cmd
                            }
                        }
                    },
                    "message": {
                        "text": f"Exploit command {i + 1}"
                    }
                })
            result["relatedLocations"] = related_locations

        return result

    def to_json(self, findings: List[Finding], indent: int = 2) -> str:
        """Generate SARIF report as JSON string.

        Args:
            findings: List of vulnerability findings.
            indent: JSON indentation level.

        Returns:
            JSON string.
        """
        report = self.generate(findings)
        return json.dumps(report, indent=indent, ensure_ascii=False)

    def save(self, findings: List[Finding], output_path: str, indent: int = 2) -> None:
        """Save SARIF report to file.

        Args:
            findings: List of vulnerability findings.
            output_path: Path to save the report.
            indent: JSON indentation level.
        """
        sarif_content = self.to_json(findings, indent)
        Path(output_path).write_text(sarif_content, encoding='utf-8')
