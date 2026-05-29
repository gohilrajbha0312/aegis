import json
from typing import Dict, Any, List
import datetime

class EnterpriseReportingEngine:
    """
    Reporting Engine.
    Generates multi-format output (JSON, SARIF, Markdown) for findings.
    """
    
    def generate_json_report(self, workflow_id: str, findings: List[Dict[str, Any]], output_path: str):
        report = {
            "workflow_id": workflow_id,
            "generated_at": datetime.datetime.now().isoformat(),
            "findings": findings
        }
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=4)
            
    def generate_sarif_report(self, workflow_id: str, findings: List[Dict[str, Any]], output_path: str):
        """Generates a SARIF format report suitable for GitHub Advanced Security integration."""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AEGIS-X",
                            "version": "2.0.0",
                            "informationUri": "https://github.com/aegisx"
                        }
                    },
                    "results": []
                }
            ]
        }
        
        for finding in findings:
            result = {
                "ruleId": finding.get("finding_type", "AEGIS-X-UNKNOWN"),
                "message": {
                    "text": finding.get("reasoning", "No description provided.")
                },
                "locations": [],
                "properties": {
                    "confidence": finding.get("confidence", 0.0),
                    "governance_class": finding.get("governance_class", "UNKNOWN")
                }
            }
            # Add evidence as locations
            for ev in finding.get("evidence", []):
                if isinstance(ev, str) and (ev.startswith("http://") or ev.startswith("https://")):
                    result["locations"].append({
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": ev
                            }
                        }
                    })
            sarif["runs"][0]["results"].append(result)
            
        with open(output_path, 'w') as f:
            json.dump(sarif, f, indent=4)

    def generate_markdown_report(self, workflow_id: str, findings: List[Dict[str, Any]], output_path: str):
        with open(output_path, 'w') as f:
            f.write(f"# AEGIS-X Enterprise Recon Report\n")
            f.write(f"**Workflow ID:** {workflow_id}\n")
            f.write(f"**Generated At:** {datetime.datetime.now().isoformat()}\n\n")
            
            f.write("## Findings\n\n")
            for i, finding in enumerate(findings):
                f.write(f"### {i+1}. {finding.get('finding_type', 'Unknown Finding')}\n")
                f.write(f"- **Confidence Score:** {finding.get('confidence', 0.0)}\n")
                f.write(f"- **Governance Class:** {finding.get('governance_class', 'PASSIVE_ANALYSIS')}\n")
                f.write(f"- **Reasoning:** {finding.get('reasoning', '')}\n")
                f.write(f"- **Recommended Action:** {finding.get('recommended_action', '')}\n")
                
                f.write("\n**Evidence Lines:**\n")
                for ev in finding.get("evidence", []):
                    f.write(f"- `{ev}`\n")
                f.write("\n---\n\n")
