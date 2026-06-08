import asyncio
import sys
import os
sys.path.append(os.path.join(os.getcwd(), 'src'))

from aegisx.agents.commander import ai_1
from aegisx.core.ui.console import ConsoleUI

async def main():
    ConsoleUI.info("Executing SINGLE AI model to check structural generation...")
    try:
        res = await asyncio.wait_for(ai_1.run("Target: example.com\nScan Mode: adaptive\nSAFE_STATE_SUMMARY:\n{}"), timeout=60.0)
        print("\n=== SINGLE AGENT SUCCESS ===")
        print(f"Output: {res.data}")
    except Exception as e:
        print(f"\n=== SINGLE AGENT FAILED ===")
        print(f"Error: {e}")

asyncio.run(main())
