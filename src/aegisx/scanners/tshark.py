import asyncio
import uuid
import json
import os
from typing import Dict, Any, List
from aegisx.scanners.base import ToolAdapter
from aegisx.core.schemas.findings import Finding

class TsharkAdapter(ToolAdapter):
    """Enterprise tshark execution wrapper for network traffic capture and analysis."""

    async def execute(self, operation: Dict[str, Any]) -> Dict[str, Any]:
        target = operation.get("target")
        interface = operation.get("interface", "eth0")
        pcap_file = operation.get("pcap_file")
        capture_duration = operation.get("duration", 10)
        
        if not target and not pcap_file:
            raise ValueError("Tshark requires a target or pcap_file")

        output_file = f"/tmp/tshark_{uuid.uuid4().hex}.json"
        
        # If a pcap file is provided, analyze it. Otherwise, perform a live capture.
        if pcap_file:
            cmd = [
                "tshark", 
                "-r", pcap_file, 
                "-T", "json", 
                "-e", "http.cookie", 
                "-e", "http.authorization", 
                "-e", "http.request.uri", 
                "-Y", "http.cookie or http.authorization"
            ]
            # Write stdout directly to file
        else:
            # Live capture on interface for demonstration
            cmd = [
                "tshark", 
                "-i", interface, 
                "-a", f"duration:{capture_duration}", 
                "-T", "json", 
                "-e", "http.cookie", 
                "-e", "http.authorization", 
                "-e", "http.request.uri", 
                "-Y", "http.cookie or http.authorization"
            ]
            
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=capture_duration + 30.0)
        except asyncio.TimeoutError:
            process.kill()
            raise TimeoutError("Tshark execution timed out")

        raw_output = stdout.decode('utf-8')
        findings = self._normalize_output(raw_output, target or "Network")
        
        return {
            "status": "success" if process.returncode == 0 else "failed",
            "findings": [f.model_dump() for f in findings]
        }

    def _normalize_output(self, raw_output: str, target: str) -> List[Finding]:
        """Convert raw Tshark JSON output into structured enterprise Findings."""
        findings = []
        if not raw_output.strip():
            return findings
            
        try:
            packets = json.loads(raw_output)
            for packet in packets:
                layers = packet.get("_source", {}).get("layers", {})
                
                cookie = layers.get("http.cookie", [])
                auth = layers.get("http.authorization", [])
                uri_list = layers.get("http.request.uri", ["Unknown"])
                uri = uri_list[0] if uri_list else "Unknown"
                
                evidence = []
                if cookie:
                    evidence.append(f"Exposed Cookie: {cookie[0]}")
                if auth:
                    evidence.append(f"Exposed Auth Header: {auth[0]}")
                    
                if evidence:
                    finding = Finding(
                        id=str(uuid.uuid4()),
                        title=f"Unencrypted Session Data Discovered on {uri}",
                        severity="CRITICAL",
                        confidence=0.98,
                        evidence=evidence,
                        source_tool="tshark",
                        cwe="CWE-319",  # Cleartext Transmission of Sensitive Information
                        affected_assets=[target],
                        exploitability="High"
                    )
                    findings.append(finding)
        except json.JSONDecodeError:
            pass # Handle invalid JSON if tshark failed
            
        return findings
