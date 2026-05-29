import asyncio
import uuid
from typing import Dict, Any, List
from aegisx.scanners.base import ToolAdapter
from aegisx.core.schemas.findings import Finding

class NmapAdapter(ToolAdapter):
    """Enterprise Nmap execution wrapper with async processing and structured normalization."""

    async def execute(self, operation: Dict[str, Any]) -> Dict[str, Any]:
        target = operation.get("target")
        if not target:
            raise ValueError("Nmap requires a target")

        # Basic fast scan for enterprise context (we avoid overly aggressive flags by default)
        cmd = ["nmap", "-T4", "-F", "-sV", "--host-timeout", "5m", target]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300.0)
        except asyncio.TimeoutError:
            process.kill()
            raise TimeoutError(f"Nmap scan timed out for {target}")

        raw_output = stdout.decode('utf-8')
        findings = self._normalize_output(raw_output, target)
        
        return {
            "status": "success" if process.returncode == 0 else "failed",
            "findings": [f.model_dump() for f in findings],
            "raw_evidence": raw_output
        }

    def _normalize_output(self, raw_output: str, target: str) -> List[Finding]:
        """Convert raw Nmap output into structured enterprise Findings."""
        findings = []
        
        # Extremely basic parsing for demonstration. 
        # In a real enterprise system, we would parse XML output.
        lines = raw_output.split('\n')
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                port = parts[0]
                service = parts[2] if len(parts) > 2 else "unknown"
                
                finding = Finding(
                    id=str(uuid.uuid4()),
                    title=f"Open Port Discovered: {port} ({service})",
                    severity="INFO",
                    confidence=0.95,
                    evidence=[line.strip()],
                    source_tool="nmap",
                    affected_assets=[target],
                    exploitability="Unknown"
                )
                findings.append(finding)
                
        return findings
