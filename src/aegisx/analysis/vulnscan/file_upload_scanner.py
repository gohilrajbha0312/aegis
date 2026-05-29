"""
AEGIS-X File Upload Scanner
Algorithm: MIME type bypass + extension bypass + content-type manipulation.
"""
import re
from aegisx.core import http_client as requests
from typing import Dict, Any, List
from io import BytesIO

from aegisx.core.ui.console import ConsoleUI

try:
    from bs4 import BeautifulSoup
    _BS4 = True
except ImportError:
    _BS4 = False


class FileUploadScanner:

    # Test files with various bypass techniques
    TEST_FILES = [
        {"name": "test.php", "content": b"<?php echo 'AEGISX_UPLOAD_TEST'; ?>", "mime": "application/x-php", "desc": "PHP shell"},
        {"name": "test.php.jpg", "content": b"<?php echo 'AEGISX_UPLOAD_TEST'; ?>", "mime": "image/jpeg", "desc": "Double extension"},
        {"name": "test.pHp", "content": b"<?php echo 'AEGISX_UPLOAD_TEST'; ?>", "mime": "image/jpeg", "desc": "Case bypass"},
        {"name": "test.php%00.jpg", "content": b"<?php echo 'AEGISX_UPLOAD_TEST'; ?>", "mime": "image/jpeg", "desc": "Null byte"},
        {"name": "test.svg", "content": b'<svg onload="alert(1)"/>', "mime": "image/svg+xml", "desc": "SVG XSS"},
        {"name": "test.html", "content": b"<script>alert(1)</script>", "mime": "text/html", "desc": "HTML upload"},
    ]

    def scan(self, target: str, routes: List[str]) -> List[Dict[str, Any]]:
        findings = []
        base_url = f"http://{target}"

        upload_endpoints = self._discover_upload_endpoints(base_url, routes)
        ConsoleUI.info(f"[FileUpload] Found {len(upload_endpoints)} upload endpoints")

        for ep in upload_endpoints:
            result = self._test_upload(base_url, ep)
            if result:
                findings.append(result)

        return findings

    def _discover_upload_endpoints(self, base_url: str, routes: List[str]) -> List[Dict]:
        endpoints = []

        # Check routes for upload-related paths
        for route in routes:
            if any(kw in route.lower() for kw in ["upload", "file", "attach", "import", "image"]):
                endpoints.append({"url": f"{base_url}{route}" if route.startswith("/") else route, "field": "file"})

        # Parse HTML forms for file inputs
        if _BS4:
            for route in routes[:10]:
                url = f"{base_url}{route}" if route.startswith("/") else route
                try:
                    resp = requests.get(url, timeout=5)
                    if resp.status_code != 200:
                        continue
                    soup = BeautifulSoup(resp.text, "html.parser")
                    for form in soup.find_all("form"):
                        file_inputs = form.find_all("input", {"type": "file"})
                        if file_inputs:
                            action = form.get("action", route)
                            if not action.startswith("http"):
                                action = f"{base_url}{action}"
                            for fi in file_inputs:
                                endpoints.append({"url": action, "field": fi.get("name", "file")})
                except Exception:
                    pass

        if not endpoints:
            endpoints = [
                {"url": f"{base_url}/upload", "field": "file"},
                {"url": f"{base_url}/api/upload", "field": "file"},
            ]

        return endpoints

    def _test_upload(self, base_url: str, endpoint: Dict) -> Dict[str, Any] | None:
        url = endpoint["url"]
        field = endpoint["field"]
        successful_uploads = []

        for test in self.TEST_FILES:
            try:
                files = {field: (test["name"], BytesIO(test["content"]), test["mime"])}
                resp = requests.post(url, files=files, timeout=10, allow_redirects=False)

                if resp.status_code in [200, 201, 301, 302]:
                    # Check if upload was accepted (not just the page rendered)
                    error_markers = ["error", "denied", "invalid", "not allowed", "rejected", "failed"]
                    resp_lower = resp.text.lower()
                    if not any(m in resp_lower for m in error_markers):
                        successful_uploads.append(test["desc"])
                        ConsoleUI.warning(f"[FileUpload] Upload accepted: {test['desc']} ({test['name']})")

                        # Try to access uploaded file
                        self._check_file_accessible(base_url, test["name"])
            except Exception:
                pass

        if successful_uploads:
            risk = "CRITICAL" if any("PHP" in u or "shell" in u for u in successful_uploads) else "HIGH"
            return {
                "finding_type": "Unrestricted File Upload",
                "base_confidence": 0.85, "consensus_score": 0.85, "score_conflict": False,
                "risk_level": risk, "governance_class": "ACTIVE_VALIDATION",
                "requires_human_approval": False,
                "recommended_validation": [
                    "Validate file type server-side using magic bytes, not just extension/MIME",
                    "Store uploads outside webroot with randomized filenames",
                    "Implement file size limits and content scanning",
                    "Disable script execution in upload directories",
                ],
                "reasoning": [
                    f"Upload endpoint {url} accepted dangerous files",
                    f"Bypasses: {', '.join(successful_uploads)}",
                ],
                "nodes": [], "edges": [],
            }
        return None

    def _check_file_accessible(self, base_url: str, filename: str):
        common_upload_dirs = ["/uploads/", "/upload/", "/files/", "/images/", "/media/", "/attachments/"]
        for d in common_upload_dirs:
            try:
                resp = requests.get(f"{base_url}{d}{filename}", timeout=3)
                if resp.status_code == 200 and "AEGISX_UPLOAD_TEST" in resp.text:
                    ConsoleUI.success(f"[FileUpload] CRITICAL: Uploaded file is directly accessible at {d}{filename}")
            except Exception:
                pass
