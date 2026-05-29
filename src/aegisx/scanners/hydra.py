import asyncio
import uuid
import json
from typing import Dict, Any, List
from aegisx.scanners.base import ToolAdapter
from aegisx.core.schemas.findings import Finding

class HydraAdapter(ToolAdapter):
    """Enterprise Hydra execution wrapper for credential brute-forcing."""

    async def execute(self, operation: Dict[str, Any]) -> Dict[str, Any]:
        target = operation.get("target")
        service = operation.get("service", "ssh")
        users_file = operation.get("users_file", "wordlists/users.txt")
        pass_file = operation.get("pass_file", "wordlists/passwords.txt")
        
        if not target:
            raise ValueError("Hydra requires a target")

        # Basic hydra command
        cmd = [
            "hydra",
            "-L", users_file,
            "-P", pass_file,
            "-t", "4",
            f"{service}://{target}",
            "-I", "-b", "json"
        ]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=600.0)
        except asyncio.TimeoutError:
            process.kill()
            raise TimeoutError(f"Hydra scan timed out for {target}")

        raw_output = stdout.decode('utf-8')
        findings = self._normalize_output(raw_output, target, service)
        
        return {
            "status": "success" if process.returncode == 0 else "failed",
            "findings": [f.model_dump() for f in findings],
            "raw_evidence": raw_output
        }

    def _normalize_output(self, raw_output: str, target: str, service: str) -> List[Finding]:
        findings = []
        try:
            data = json.loads(raw_output)
            results = data.get("results", [])
            for res in results:
                username = res.get("login")
                password = res.get("password")
                if username and password:
                    finding = Finding(
                        id=str(uuid.uuid4()),
                        title=f"Brute Force Success: Default Credentials on {service}",
                        severity="CRITICAL",
                        confidence=1.0,
                        evidence=[f"Service: {service}", f"Username: {username}", f"Password: {password}"],
                        source_tool="hydra",
                        cwe="CWE-521",
                        affected_assets=[target],
                        exploitability="High"
                    )
                    findings.append(finding)
        except json.JSONDecodeError:
            pass # Standard output fallback could be parsed here
        return findings
