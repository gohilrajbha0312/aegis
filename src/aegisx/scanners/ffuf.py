import asyncio
import uuid
import json
import os
from typing import Dict, Any, List
from aegisx.scanners.base import ToolAdapter
from aegisx.core.schemas.findings import Finding

class FFUFAdapter(ToolAdapter):
    """Enterprise FFUF execution wrapper for route fuzzing and discovery."""

    async def execute(self, operation: Dict[str, Any]) -> Dict[str, Any]:
        target = operation.get("target")
        wordlist = operation.get("wordlist", "wordlists/common.txt")
        is_targeted = operation.get("is_targeted", False)
        
        if not target:
            raise ValueError("FFUF requires a target")
            
        if wordlist == "wordlists/common.txt" and not is_targeted:
            raise ValueError("AEGIS-X Policy: Blind fuzzing with common wordlists is prohibited. The AI must supply a targeted wordlist or specific route pattern.")
            
        fuzz_url = target if "FUZZ" in target else target.rstrip('/') + "/FUZZ"

        # Create a temporary output file for JSON results
        output_file = f"/tmp/ffuf_{uuid.uuid4().hex}.json"
        
        cmd = [
            "ffuf", 
            "-u", fuzz_url, 
            "-w", wordlist, 
            "-mc", "200,204,301,302,307,401,403,405,500",
            "-o", output_file,
            "-of", "json",
            "-silent"
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
            raise TimeoutError(f"FFUF scan timed out for {target}")

        findings = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                try:
                    data = json.load(f)
                    findings = self._normalize_output(data, target)
                except json.JSONDecodeError:
                    pass
            os.remove(output_file)
        
        return {
            "status": "success" if process.returncode == 0 else "failed",
            "findings": [f.model_dump() for f in findings]
        }

    def _normalize_output(self, data: Dict[str, Any], target: str) -> List[Finding]:
        findings = []
        results = data.get("results", [])
        
        for result in results:
            status = result.get("status")
            url = result.get("url")
            
            finding = Finding(
                id=str(uuid.uuid4()),
                title=f"Discovered Endpoint: {url} (HTTP {status})",
                severity="INFO" if status in [200, 301, 302] else "LOW",
                confidence=0.9,
                evidence=[f"Status: {status}", f"Content-Length: {result.get('length')}"],
                source_tool="ffuf",
                affected_assets=[target],
                exploitability="N/A"
            )
            findings.append(finding)
                
        return findings
