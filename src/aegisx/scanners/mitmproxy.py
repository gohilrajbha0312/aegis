import asyncio
import uuid
import json
import os
from typing import Dict, Any, List
from aegisx.scanners.base import ToolAdapter
from aegisx.core.schemas.findings import Finding

class MitmProxyAdapter(ToolAdapter):
    """
    Adapter for capturing network traffic using mitmdump (part of mitmproxy).
    Captures HTTP flows into a structured format for the AI to analyze and mutate.
    """

    async def execute(self, operation: Dict[str, Any]) -> Dict[str, Any]:
        target = operation.get("target")
        capture_duration = operation.get("duration", 15)
        port = operation.get("port", 8080)
        
        output_file = f"/tmp/aegisx_mitm_{uuid.uuid4().hex}.flow"
        
        # Start mitmdump in the background, listening on a specific port and saving to a file
        cmd = [
            "mitmdump",
            "-p", str(port),
            "-w", output_file,
            "--set", "block_global=false" # Allow external requests if needed
        ]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            # We wait for the capture duration
            await asyncio.sleep(capture_duration)
            # Then we gracefully terminate it
            process.terminate()
            await process.wait()
        except Exception as e:
            process.kill()
            raise RuntimeError(f"MitmProxy execution failed: {e}")

        # In a real scenario we would parse the .flow file (which is in tnetstring format)
        # using the mitmproxy.io module.
        # For this demonstration, we'll simulate the extraction of raw HTTP requests.
        
        captured_requests = self._extract_requests(output_file, target)
        
        return {
            "status": "success",
            "captured_requests": captured_requests
        }

    def _extract_requests(self, flow_file: str, target: str) -> List[str]:
        """
        Simulate extracting raw HTTP requests from the mitmproxy flow file.
        In reality, this would use mitmproxy.io.FlowReader to iterate through the captured flows.
        """
        
        # Simulated raw HTTP requests that might be captured
        return [
            f"""GET /api/v1/user/105/profile HTTP/1.1
Host: {target}
Authorization: Bearer mock_token_for_user_105
Accept: application/json
""",
            f"""POST /api/v1/admin/settings HTTP/1.1
Host: {target}
Authorization: Bearer mock_token_for_user_105
Content-Type: application/json

{{"role": "user", "theme": "dark"}}
"""
        ]
