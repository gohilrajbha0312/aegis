from aegisx.core.models import default_model
import os
import json
from typing import Dict, Any, List
from pydantic_ai import Agent
from aegisx.agents.base import BaseAgent
from aegisx.core.schemas.findings import Finding

import markdown2
from weasyprint import HTML, CSS

# We use Gemini for reporting since it requires synthesizing large text
reporting_ai = Agent(
    default_model,
    system_prompt=(
        "You are the AEGIS-X Enterprise Reporting Engine. "
        "Your job is to take a raw list of technical findings and convert them into a professional, "
        "OWASP-formatted penetration testing report in Markdown. "
        "The report MUST include:\n"
        "1. Executive Summary\n"
        "2. Scope and Methodology\n"
        "3. Threat Model\n"
        "4. Technical Findings Breakdown (grouped by severity, must include raw evidence/credentials if any)\n"
        "5. Actionable Mitigation Strategies\n\n"
        "IMPORTANT: If there are exposed credentials, session tokens, or brute-force results in the findings, "
        "you MUST highlight them in a code block and treat them as visual evidence/screenshots.\n"
        "Do NOT return a JSON object, just raw beautifully formatted Markdown."
    )
)

CSS_STYLES = """
body { font-family: 'Helvetica', 'Arial', sans-serif; color: #333; line-height: 1.6; padding: 20px; }
h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
h2 { color: #2980b9; margin-top: 30px; }
h3 { color: #16a085; }
code { background-color: #f8f9fa; padding: 2px 4px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 0.9em; color: #e74c3c; }
pre { background-color: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: 'Courier New', monospace; font-size: 0.85em; }
pre code { background-color: transparent; color: inherit; padding: 0; }
blockquote { border-left: 4px solid #f39c12; margin: 0; padding-left: 15px; color: #7f8c8d; }
table { width: 100%; border-collapse: collapse; margin: 20px 0; }
th, td { border: 1px solid #bdc3c7; padding: 12px; text-align: left; }
th { background-color: #ecf0f1; color: #2c3e50; }
"""

class ReportingAgent(BaseAgent):
    """
    Ingests all findings from the operation state and generates
    a final OWASP PDF penetration test report using the AI.
    """
    
    def __init__(self):
        super().__init__(agent_id="ReportingAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        target = state.get("target", "unknown_target")
        findings: List[Finding] = state.get("findings", [])
        
        self.log_action("start_reporting", {"target": target, "findings_count": len(findings)})
        
        if not findings:
            self.log_action("skip_reporting", {"reason": "No findings to report."})
            return {"phase": "reporting_skipped"}
            
        # Serialize findings for the AI
        findings_json = []
        for f in findings:
            if isinstance(f, dict):
                findings_json.append(f)
            else:
                findings_json.append(f.model_dump())
                
        prompt = f"Target: {target}\n\nPlease generate the report based on these findings:\n{json.dumps(findings_json, indent=2)}"
        
        # Call AI to generate report
        result = await reporting_ai.run(prompt)
        markdown_report = result.output
        
        # Convert Markdown to HTML
        html_content = markdown2.markdown(markdown_report, extras=["tables", "fenced-code-blocks", "cuddled-lists"])
        full_html = f"<html><head><title>AEGIS-X Report</title></head><body>{html_content}</body></html>"
        
        # Save to disk
        reports_dir = os.path.join(os.getcwd(), "runtime", "reports")
        os.makedirs(reports_dir, exist_ok=True)
        
        safe_target = target.replace("http://", "").replace("https://", "").replace("/", "_").replace(":", "_")
        md_path = os.path.join(reports_dir, f"report_{safe_target}.md")
        pdf_path = os.path.join(reports_dir, f"report_{safe_target}.pdf")
        
        # Save markdown as backup
        with open(md_path, "w") as f:
            f.write(markdown_report)
            
        # Generate PDF
        HTML(string=full_html).write_pdf(pdf_path, stylesheets=[CSS(string=CSS_STYLES)])
            
        self.log_action("pdf_report_generated", {"path": pdf_path})
        
        return {
            "phase": "reporting_complete",
            "report_path": pdf_path
        }
