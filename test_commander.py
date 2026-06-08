import asyncio
import sys
import os
sys.path.append(os.path.join(os.getcwd(), 'src'))

from aegisx.agents.commander import CommanderAgent
from aegisx.core.ui.console import ConsoleUI

async def main():
    ConsoleUI.info("Initializing Commander Agent for Multi-Agent Test...")
    commander = CommanderAgent()
    
    # Mock WorkflowState dict
    state = {
        "target": "example.com",
        "current_stage": "Reconnaissance",
        "findings": [],
        "completed_agents": [],
        "routes": ["/login", "/api/users", "/admin/dashboard"],
        "parameters": [{"name": "id", "type": "int"}],
        "sessions": ["jwt_token_123"],
    }
    
    ConsoleUI.info("Executing CommanderAgent.process() with 3 concurrent AI models...")
    try:
        result = await commander.process(state)
        print("\n=== MULTI-AGENT EXECUTION SUCCESS ===")
        print(f"Status: {result.get('status')}")
        pipeline = result.get('pipeline', {})
        print(f"Phase Transition: {pipeline.get('phase_transition')}")
        print(f"Next Actions: {[a.get('agent') for a in pipeline.get('next_actions', [])]}")
        print(f"Reasoning: {pipeline.get('reasoning')}")
    except Exception as e:
        print(f"\n=== MULTI-AGENT EXECUTION FAILED ===")
        print(f"Error: {e}")

asyncio.run(main())
