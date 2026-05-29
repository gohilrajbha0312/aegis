import asyncio
from aegisx.scanners.nmap import NmapAdapter
from aegisx.telemetry.streamer import RedisEventBus
from aegisx.core.schemas.events import EventMessage

async def main():
    print("[*] Initializing AEGIS-X Integration Test...")
    
    # 1. Start Event Bus
    bus = RedisEventBus()
    await bus.connect()
    
    # Send Start Event
    start_event = EventMessage(
        phase="recon_testing",
        severity="INFO",
        message="Starting Nmap Adapter Integration Test",
        metadata={"target": "127.0.0.1"}
    )
    await bus.publish_event("aegisx_events", start_event)
    print(f"[+] Published Event: {start_event.message}")
    
    # 2. Initialize Adapter
    print("\n[*] Initializing Nmap Adapter...")
    adapter = NmapAdapter()
    
    print("[*] Executing Nmap scan against 127.0.0.1 (timeout 5m)...")
    try:
        results = await adapter.execute({"target": "127.0.0.1"})
        print(f"[+] Scan Complete! Status: {results['status']}")
        
        print(f"[*] Found {len(results['findings'])} structured findings:")
        for finding in results['findings']:
            print(f"    - [{finding['severity']}] {finding['title']}")
            
        # Send Completion Event
        end_event = EventMessage(
            phase="recon_testing",
            severity="INFO",
            message=f"Nmap scan completed successfully with {len(results['findings'])} findings",
            metadata={"findings_count": len(results['findings'])}
        )
        await bus.publish_event("aegisx_events", end_event)
            
    except Exception as e:
        print(f"[-] Error during execution: {e}")
        
    await bus.close()

if __name__ == "__main__":
    asyncio.run(main())
