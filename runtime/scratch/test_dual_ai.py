import asyncio
import os
import time
from dotenv import load_dotenv

# Load env vars
load_dotenv()

from aegisx.agents.commander import commander_ai, nemotron_ai, DynamicPipeline

async def main():
    print("[*] Starting Dual-AI Real-Time Verification...")
    
    gemini_key = os.getenv("GEMINI_API_KEY")
    or_key = os.getenv("OPENROUTER_API_KEY")
    
    if not gemini_key or not or_key:
        print("[-] Missing API keys in .env. Both GEMINI_API_KEY and OPENROUTER_API_KEY are required for this test.")
        return
        
    # We must set GOOGLE_API_KEY for pydantic_ai google provider
    os.environ["GOOGLE_API_KEY"] = gemini_key
    
    prompt = "Target: 192.168.1.1\nCurrent Findings:\n- [INFO] Port 80 Open\n- [INFO] Found login page at /admin\nPlease schedule the next actions."
    
    print("\n[+] Querying both AIs concurrently...")
    start_time = time.time()
    
    # Run both simultaneously
    gemini_task = asyncio.create_task(commander_ai.run(prompt))
    nemotron_task = asyncio.create_task(nemotron_ai.run(prompt))
    
    # Keep track of which task is which for logging
    task_map = {gemini_task: "Gemini", nemotron_task: "Nemotron"}
    
    # Wait for FIRST_COMPLETED
    done, pending = await asyncio.wait(
        [gemini_task, nemotron_task],
        return_when=asyncio.FIRST_COMPLETED
    )
    
    winner_task = list(done)[0]
    winner_name = task_map[winner_task]
    elapsed = time.time() - start_time
    
    print(f"\n[+] 🏆 WINNER: {winner_name} responded first in {elapsed:.2f} seconds!")
    
    # Cancel the loser
    for task in pending:
        loser_name = task_map[task]
        print(f"[!] Cancelling pending task for {loser_name}...")
        task.cancel()
        
    try:
        result = winner_task.result()
        pipeline: DynamicPipeline = result.output
        print("\n[*] Resulting Pipeline from Winner:")
        print(f"    Actions: {pipeline.next_actions}")
        print(f"    Reasoning: {pipeline.reasoning}")
        print(f"    Requires Approval: {pipeline.requires_approval}")
    except Exception as e:
        print(f"[-] Error parsing winner result: {e}")

if __name__ == "__main__":
    asyncio.run(main())
