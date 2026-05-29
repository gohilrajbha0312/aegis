import subprocess
from typing import Dict, Any, List

from aegisx.core.ui.console import ConsoleUI

class CommandGateway:
    """
    Penetration Testing Tool Execution Engine.
    Shows each command and asks for per-tool or session-wide approval, then streams output live.
    """
    _session_allowed = False  # Ask for approval by default
    _session_denied = False   # Deny all for remainder of session

    @classmethod
    def execute(cls, cmd: List[str], timeout: int = 120, description: str = "") -> Dict[str, Any]:
        cmd_str = " ".join(cmd)

        if cls._session_denied:
            ConsoleUI.error("Execution denied (session-wide deny active).")
            return {
                "success": False,
                "stdout": "",
                "stderr": "Execution denied for this session by operator.",
                "command": cmd_str
            }

        if not cls._session_allowed:
            while True:
                choice = ConsoleUI.approval_gateway(description, cmd_str)
                if choice == "1":
                    ConsoleUI.success("Execution allowed once.")
                    break
                elif choice == "2":
                    ConsoleUI.success("Execution allowed for the duration of this session.")
                    cls._session_allowed = True
                    break
                elif choice == "3":
                    ConsoleUI.error("Execution denied.")
                    return {
                        "success": False,
                        "stdout": "",
                        "stderr": "Execution denied by operator.",
                        "command": cmd_str
                    }
                elif choice == "4":
                    cls._session_denied = True
                    ConsoleUI.error("All further executions denied for this session.")
                    return {
                        "success": False,
                        "stdout": "",
                        "stderr": "Execution denied for this session by operator.",
                        "command": cmd_str
                    }
                else:
                    ConsoleUI.warning("Invalid selection. Please choose 1, 2, 3, or 4.")
        else:
            ConsoleUI.header("EXECUTION GATEWAY")
            if description:
                ConsoleUI.info(f"Context: {description}")
            ConsoleUI.info("Executing Command:")
            ConsoleUI.command(cmd_str)

        # Execute with live streaming
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            stdout_lines = []
            if process.stdout:
                for line in iter(process.stdout.readline, ''):
                    clean_line = line.rstrip()
                    ConsoleUI.stream_line(clean_line)
                    stdout_lines.append(clean_line)

            process.wait(timeout=timeout)
            stderr_out = process.stderr.read() if process.stderr else ""

            return {
                "success": process.returncode == 0,
                "stdout": "\n".join(stdout_lines),
                "stderr": stderr_out,
                "returncode": process.returncode,
                "command": cmd_str
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Execution timed out after {timeout} seconds.",
                "returncode": -1,
                "command": cmd_str
            }
        except FileNotFoundError:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Binary '{cmd[0]}' not found. Is it installed in $PATH?",
                "returncode": -1,
                "command": cmd_str
            }
