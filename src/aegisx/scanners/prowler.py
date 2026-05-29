import asyncio
import uuid
import json
import os
from typing import Dict, Any, List
from aegisx.scanners.base import ToolAdapter
from aegisx.core.schemas.findings import Finding

class ProwlerAdapter(ToolAdapter):
    """Enterprise Prowler execution wrapper for cloud posture scanning."""

    async def execute(self, operation: Dict[str, Any]) -> Dict[str, Any]:
        provider = operation.get("provider", "aws")
        
        output_dir = f"/tmp/prowler_{uuid.uuid4().hex}"
        
        cmd = [
            "prowler",
            provider,
            "--json-asff",
            "-M", "json",
            "-o", output_dir
        ]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            await asyncio.wait_for(process.communicate(), timeout=900.0)
        except asyncio.TimeoutError:
            process.kill()
            raise TimeoutError("Prowler scan timed out")

        findings = []
        if os.path.exists(output_dir):
            for file in os.listdir(output_dir):
                if file.endswith('.json'):
                    with open(os.path.join(output_dir, file), 'r') as f:
                        try:
                            data = json.load(f)
                            findings.extend(self._normalize_output(data, provider))
                        except json.JSONDecodeError:
                            pass
            # Cleanup output dir...
            
        return {
            "status": "success",
            "findings": [f.model_dump() for f in findings]
        }

    def _normalize_output(self, data: List[Dict[str, Any]], provider: str) -> List[Finding]:
        findings = []
        for res in data:
            if res.get("Status") == "FAIL":
                title = res.get("Title", "Cloud Misconfiguration")
                severity = res.get("Severity", "Medium").upper()
                finding = Finding(
                    id=str(uuid.uuid4()),
                    title=f"Cloud Posture: {title}",
                    severity=severity,
                    confidence=0.9,
                    evidence=[f"Resource: {res.get('ResourceArn')}", f"Notes: {res.get('Notes')}"],
                    source_tool="prowler",
                    affected_assets=[provider],
                    exploitability="Varies"
                )
                findings.append(finding)
        return findings
