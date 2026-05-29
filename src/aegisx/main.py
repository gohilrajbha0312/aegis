import argparse
import asyncio
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.theme import Theme
from rich import box
import time

from aegisx.agents.commander import CommanderAgent
from aegisx.knowledge.vector_memory import VectorMemory

# Define a sleek enterprise theme
custom_theme = Theme({
    "info": "dim cyan",
    "warning": "magenta",
    "danger": "bold red",
    "success": "bold green",
    "primary": "cyan",
    "highlight": "yellow"
})

console = Console(theme=custom_theme, style="on black")

ASCII_BANNER = """
    █████╗ ███████╗ ██████╗ ██╗███████╗    ██╗  ██╗
   ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝    ╚██╗██╔╝
   ███████║█████╗  ██║  ███╗██║███████╗     ╚███╔╝ 
   ██╔══██║██╔══╝  ██║   ██║██║╚════██║     ██╔██╗ 
   ██║  ██║███████╗╚██████╔╝██║███████║    ██╔╝ ██╗
   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝    ╚═╝  ╚═╝
     Advanced Security Research Engine - v1.0.0
"""

async def run_scan(target: str, auto_approve: bool):
    # Print stylish banner
    console.print(Panel(
        Text(ASCII_BANNER, justify="center", style="primary"), 
        border_style="primary", 
        box=box.DOUBLE_EDGE
    ))
    console.print(f"[primary]Target Configuration:[/primary] [highlight]{target}[/highlight]\n")
    
    # Initialize Core Engines with a status spinner
    with console.status("[info]Initializing AI Memory Modules...[/info]", spinner="point"):
        VectorMemory()
        time.sleep(1) # Visual pacing
    
    commander = CommanderAgent()
    state = {"target": target, "findings": []}
    
    console.print(f"\n[success]▶ Cognitive Core Initialized. Starting Orchestration...[/success]\n")
    
    session_allow = False
    session_deny = False
    
    # Simple simulation loop for the CLI
    for phase in range(1, 4):
        console.print(f"─" * 60, style="info")
        console.print(f"  [warning]PHASE {phase} EXECUTION[/warning]")
        console.print(f"─" * 60, style="info")
        
        # Wrapping AI reasoning in a spinner
        with console.status("[primary]AI is evaluating state and generating dynamic pipeline...[/primary]", spinner="bouncingBar"):
            result = await commander.process(state)
            
        status = result.get("status")
        pipeline = result.get("pipeline", {})
        
        # Enhanced Table
        table = Table(title="Generated Pipeline Workflow", box=box.HEAVY_EDGE, border_style="primary", show_lines=True)
        table.add_column("Agent Module", style="cyan", justify="left")
        table.add_column("AI Reasoning", style="white", justify="left")
        
        for action in pipeline.get("next_actions", []):
            table.add_row(f"[bold]{action}[/bold]", pipeline.get("reasoning", ""))
            
        console.print(table)
        
        if status == "WAITING_FOR_APPROVAL" and not auto_approve:
            if session_deny:
                console.print("\n[danger]✖ Auto-denying action (Session Deny active).[/danger]")
                break
                
            if session_allow:
                console.print("\n[success]✔ Auto-allowing action (Session Allow active).[/success]\n")
            else:
                approval_panel = Panel(
                    "[white]High-risk cognitive agents scheduled. Autonomous execution paused.[/white]",
                    title="[bold red]ACTION REQUIRED[/bold red]",
                    border_style="red",
                    box=box.HEAVY,
                    style="on grey11"
                )
                console.print(approval_panel)
                print("Please authorize execution:")
                print("  [1] Allow once")
                print("  [2] Allow for this session")
                print("  [3] Deny this action")
                print("  [4] Deny for this session")
                
                while True:
                    choice = input("[?] Selection (1/2/3/4): ").strip()
                    if choice == "1":
                        console.print("\n[success]✔ Execution approved once. Releasing pipeline...[/success]\n")
                        break
                    elif choice == "2":
                        session_allow = True
                        console.print("\n[success]✔ Execution approved for this session. Releasing pipeline...[/success]\n")
                        break
                    elif choice == "3":
                        console.print("\n[danger]✖ Execution aborted by human operator.[/danger]")
                        break
                    elif choice == "4":
                        session_deny = True
                        console.print("\n[danger]✖ All further executions denied for this session.[/danger]")
                        break
                    else:
                        print("Invalid selection. Please enter 1, 2, 3, or 4.")
                
                if choice in ["3", "4"]:
                    break
            
        # Wrap execution in spinner with bracket highlighting
        exec_agents = ', '.join(pipeline.get('next_actions', []))
        with console.status(f"[info]Executing \\[[highlight]{exec_agents}[/highlight]\\]...[/info]", spinner="aesthetic"):
            await asyncio.sleep(2) # Simulate execution time
        
        console.print("[success]✔ Phase completed successfully.[/success]\n")
        break # Break simulation loop early
        
    console.print(Panel("[bold cyan]AEGIS-X Orchestration Complete.[/bold cyan]", border_style="cyan", box=box.ROUNDED))


def main():
    parser = argparse.ArgumentParser(description="AEGIS-X Security Platform CLI")
    parser.add_argument("-t", "--target", required=True, help="Target URL or IP (e.g., example.com)")
    parser.add_argument("--auto-approve", action="store_true", help="Bypass HITL approvals (Use with caution)")
    
    args = parser.parse_args()
    
    try:
        asyncio.run(run_scan(args.target, args.auto_approve))
    except KeyboardInterrupt:
        console.print("\n[danger]✖ Scan interrupted by user.[/danger]")

if __name__ == "__main__":
    main()
