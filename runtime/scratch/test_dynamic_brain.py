import asyncio
from aegisx.agents.commander import CommanderAgent, DynamicPipeline
from aegisx.agents.auth_analyzer import AuthAnalyzerAgent
from aegisx.scanners.ffuf import FFUFAdapter
from aegisx.core.schemas.findings import Finding
from pydantic_ai.models.test import TestModel

async def main():
    print("[*] Initializing AEGIS-X Dynamic Brain Test...")
    
    # We use TestModel to simulate the Gemini API responding with a specific schema
    # In production, this would use the real gemini-2.5 model
    mock_pipeline = DynamicPipeline(
        next_actions=["AuthAnalyzerAgent"],
        reasoning="I detected a JWT token in the session state. Specialized AuthAnalyzer is required to test for None-alg vulnerabilities. This is high risk and needs approval.",
        requires_approval=True
    )
    
    # PydanticAI test model uses specific injection mechanics. For simplicity, we just inject the object.
    test_model = TestModel(custom_output_args=mock_pipeline)
    
    commander = CommanderAgent(model_override=test_model)
    
    # 1. Simulate an incoming finding from an earlier ReconAgent pass
    mock_finding = Finding(
        id="f-1",
        title="Discovered Login Endpoint",
        severity="INFO",
        confidence=1.0,
        source_tool="nmap",
        exploitability="N/A"
    )
    
    state = {
        "target": "127.0.0.1",
        "findings": [mock_finding]
    }
    
    # 2. Commander Evaluates
    print("[*] Commander evaluating state...")
    decision = await commander.process(state)
    
    print("\n[+] Commander Decision:")
    print(f"    Status: {decision['status']}")
    print(f"    Actions: {decision['pipeline']['next_actions']}")
    print(f"    Reasoning: {decision['pipeline']['reasoning']}")
    
    # 3. Simulate HITL execution pause
    if decision['status'] == "WAITING_FOR_APPROVAL":
        print("\n[!] HITL Triggered. Execution Paused.")
        print("[?] Operator Action Required: Approve AuthAnalyzerAgent? (Simulating 'yes'...)")
        
        # 4. Operator approves, execution continues to AuthAnalyzer
        print("\n[*] Initializing AuthAnalyzerAgent...")
        auth_agent = AuthAnalyzerAgent()
        
        # We inject a fake token to trigger the finding
        auth_state = {
            "target": "127.0.0.1",
            "auth_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature"
        }
        
        auth_results = await auth_agent.process(auth_state)
        print(f"[+] Auth Analysis Complete! Found {len(auth_results['findings'])} logical flaws.")
        for f in auth_results['findings']:
            print(f"    - [{f.severity}] {f.title}")
            
    # 5. Verify FFUF blocks blind fuzzing
    print("\n[*] Verifying FFUF strict targeting policy...")
    ffuf = FFUFAdapter()
    try:
        await ffuf.execute({"target": "127.0.0.1", "wordlist": "wordlists/common.txt"})
    except ValueError as e:
        print(f"[+] FFUF successfully blocked blind fuzzing: {e}")

if __name__ == "__main__":
    asyncio.run(main())
