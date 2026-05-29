import asyncio
import uuid
import json
import os
from typing import Dict, Any, List
from aegisx.scanners.base import ToolAdapter
from aegisx.core.schemas.findings import Finding

class SemgrepAdapter(ToolAdapter):
    """Enterprise Semgrep execution wrapper for SAST."""

    async def execute(self, operation: Dict[str, Any]) -> Dict[str, Any]:
        target_dir = operation.get("target_dir", ".")
        
        output_file = f"/tmp/semgrep_{uuid.uuid4().hex}.json"
        
        cmd = [
            "semgrep",
            "scan",
            "--config", "auto",
            "--json",
            "--output", output_file,
            target_dir
        ]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            await asyncio.wait_for(process.communicate(), timeout=300.0)
        except asyncio.TimeoutError:
            process.kill()
            raise TimeoutError("Semgrep scan timed out")

        findings = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                try:
                    data = json.load(f)
                    findings = self._normalize_output(data, target_dir)
                except json.JSONDecodeError:
                    pass
            os.remove(output_file)
        
        return {
            "status": "success",
            "findings": [f.model_dump() for f in findings]
        }

    def _normalize_output(self, data: Dict[str, Any], target_dir: str) -> List[Finding]:
        findings = []
        results = data.get("results", [])
        for res in results:
            path = res.get("path")
            msg = res.get("extra", {}).get("message", "SAST Finding")
            severity = res.get("extra", {}).get("severity", "INFO")
            lines = res.get("extra", {}).get("lines", "")
            
            mapped_sev = "HIGH" if severity == "ERROR" else "MEDIUM" if severity == "WARNING" else "LOW"
            
            finding = Finding(
                id=str(uuid.uuid4()),
                title=f"Code Vulnerability: {res.get('check_id')}",
                severity=mapped_sev,
                confidence=0.8,
                evidence=[f"File: {path}", f"Message: {msg}", f"Snippet:\n{lines}"],
                source_tool="semgrep",
                affected_assets=[target_dir],
                exploitability="Unknown"
            )
            findings.append(finding)
        return findings
