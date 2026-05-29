import asyncio
import uuid
import json
from typing import Dict, Any, List
from aegisx.scanners.base import ToolAdapter
from aegisx.core.schemas.findings import Finding

class NucleiAdapter(ToolAdapter):
    """Enterprise Nuclei execution wrapper with structured JSON extraction."""

    async def execute(self, operation: Dict[str, Any]) -> Dict[str, Any]:
        target = operation.get("target")
        tags = operation.get("tags", "cve,vuln,misconfig")
        
        if not target:
            raise ValueError("Nuclei requires a target")

        # Ensure we output as JSON for deterministic parsing
        cmd = ["nuclei", "-u", target, "-tags", tags, "-jsonl", "-silent"]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=600.0)
        except asyncio.TimeoutError:
            process.kill()
            raise TimeoutError(f"Nuclei scan timed out for {target}")

        raw_output = stdout.decode('utf-8')
        findings = self._normalize_output(raw_output)
        
        return {
            "status": "success" if process.returncode == 0 else "failed",
            "findings": [f.model_dump() for f in findings],
            "raw_evidence": raw_output[:1000] # Trim evidence
        }

    def _normalize_output(self, raw_jsonl: str) -> List[Finding]:
        findings = []
        for line in raw_jsonl.split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                info = data.get("info", {})
                
                finding = Finding(
                    id=str(uuid.uuid4()),
                    title=info.get("name", "Unknown Vulnerability"),
                    severity=info.get("severity", "info").upper(),
                    confidence=1.0, # Nuclei matches are generally high confidence
                    evidence=[data.get("matched-at", ""), data.get("extracted-results", [])],
                    source_tool="nuclei",
                    cwe=info.get("classification", {}).get("cwe-id", [""])[0] if info.get("classification") else None,
                    affected_assets=[data.get("host", "unknown")],
                    exploitability="High" if info.get("severity") in ["critical", "high"] else "Low"
                )
                findings.append(finding)
            except json.JSONDecodeError:
                continue
                
        return findings
