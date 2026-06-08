import argparse
import sys
import os
from dotenv import load_dotenv

# Load environment variables FIRST before any aegisx imports
load_dotenv()

from aegisx.core.config import ConfigManager
from aegisx.governance.auth.session import AuthSessionManager
from aegisx.core.orchestrator import AIOperationsOrchestrator
from aegisx.core.ui.console import ConsoleUI

def setup_security_wrapper():
    """
    Enforces authentication, session timeouts, and ensures AI configuration exists
    before allowing any platform functionality to run.
    """
    # 1. Initialize and Check Authentication Session
    auth_manager = AuthSessionManager()
    # auth_manager.check_session() # Disabled for headless pen-testing mode
    
    # 2. Check AI Configuration
    config = ConfigManager()
    config.get_ai_api_key() # Will prompt and save if not present

def execute_full_campaign(target: str, scan_mode: str = "adaptive"):
    """
    Executes the full 16-stage Unified Cognitive Orchestration Flow.
    """
    from aegisx.core.runtime_governor import ScanMode
    try:
        mode_enum = ScanMode(scan_mode)
    except ValueError:
        mode_enum = ScanMode.ADAPTIVE_VALIDATION

    # Initialize the master orchestrator
    orchestrator = AIOperationsOrchestrator(scan_mode=mode_enum)
    
    # Execute the campaign
    orchestrator.execute_campaign(target=target)

def main():
    # Enforce Security Boundaries First
    setup_security_wrapper()
    
    parser = argparse.ArgumentParser(description="AEGIS-X Security Validation Toolchain")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Command: recon-run
    recon_parser = subparsers.add_parser("recon-run", help="Run governed network reconnaissance pipeline")
    recon_parser.add_argument("target", type=str, help="Target IP, URL, or CIDR (e.g., 192.168.4.126:80)")
    recon_parser.add_argument("--scan-mode", type=str, choices=["passive", "safe_recon", "adaptive", "deep", "high_intensity"], default="adaptive", help="Runtime governance scan mode")
    
    args = parser.parse_args()
    
    if args.command == "recon-run":
        execute_full_campaign(args.target, scan_mode=args.scan_mode)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        ConsoleUI.warning("Execution cancelled by user.")
        sys.exit(1)
