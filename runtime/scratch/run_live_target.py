import asyncio
import os
import sys
from urllib.parse import urlparse
from aegisx.agents.commander import CommanderAgent
from aegisx.agents.recon import ReconAgent
from aegisx.agents.auth_analyzer import AuthAnalyzerAgent
from aegisx.agents.reporting import ReportingAgent
from aegisx.telemetry.streamer import RedisEventBus
from aegisx.core.schemas.events import EventMessage

async def main():
    target_url = "http://192.168.4.126:3000/"
    parsed = urlparse(target_url)
    target_ip = parsed.hostname or target_url
    
    print(f"[*] Initializing Live AEGIS-X Operation against {target_url}")
    
    # Setup API Key
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("[-] GEMINI_API_KEY not set. Using dummy for test logic.")
        os.environ["GOOGLE_API_KEY"] = "dummy"
    else:
        os.environ["GOOGLE_API_KEY"] = api_key
        
    or_api_key = os.getenv("OPENROUTER_API_KEY")
    if not or_api_key:
        print("[-] OPENROUTER_API_KEY not set. Using dummy for test logic.")
        os.environ["OPENROUTER_API_KEY"] = "dummy"

    bus = RedisEventBus()
    await bus.connect()
    
    # Phase 1: Reconnaissance
    print("\n[+] [PHASE 1] Initializing ReconAgent...")
    recon = ReconAgent()
    
    # Nmap needs the IP
    state = {"target": target_ip}
    recon_results = await recon.process(state)
    
    findings = recon_results.get("findings", [])
    print(f"[+] Recon complete. Found {len(findings)} initial findings.")
    for f in findings:
        print(f"    - [{f['severity']}] {f['title']}")
        
    # Phase 2: Commander AI Analysis
    print("\n[+] [PHASE 2] Handing state to AI Commander for dynamic pipeline generation...")
    commander = CommanderAgent()
    state["findings"] = findings
    state["target"] = target_url # Give Commander the full URL context
    
    try:
        decision = await commander.process(state)
        
        print("\n[+] AI Commander Decision:")
        print(f"    Status: {decision['status']}")
        print(f"    Next Actions: {decision['pipeline']['next_actions']}")
        print(f"    Reasoning: {decision['pipeline']['reasoning']}")
        
        # Execute dynamically scheduled agents
        if "AuthAnalyzerAgent" in decision['pipeline']['next_actions']:
            if decision['status'] == "WAITING_FOR_APPROVAL":
                print("\n[!] HITL Triggered: High-Risk Action (Auth Analysis)")
                print("[?] Simulating Operator Approval... APPROVED.")
                
            print("\n[+] [PHASE 3] Executing AuthAnalyzerAgent...")
            auth_agent = AuthAnalyzerAgent()
            
            # Simulate a token found on port 3000
            auth_state = {
                "target": target_url,
                "auth_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy_token_found_on_port_3000"
            }
            auth_results = await auth_agent.process(auth_state)
            
            print(f"[+] Auth Analysis complete. Found {len(auth_results['findings'])} logical flaws.")
            for f in auth_results['findings']:
                print(f"    - [{f.severity}] {f.title}")
                state["findings"].extend(auth_results['findings'])
                
        print("\n[+] [PHASE 4] Handing execution to ReportingAgent...")
        reporter = ReportingAgent()
        report_result = await reporter.process(state)
        print(f"[+] Reporting Complete! Saved to: {report_result.get('report_path')}")
                
    except Exception as e:
        print(f"[-] AI Commander Error: {e}")
        print("Ensure GOOGLE_API_KEY or GEMINI_API_KEY is valid.")
        
    await bus.close()
    print("\n[*] Operation Complete.")

if __name__ == "__main__":
    asyncio.run(main())
