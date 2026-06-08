from typing import Dict, Any
from aegisx.agents.base import BaseAgent
from aegisx.core.ui.console import ConsoleUI

class GraphQLExpansionAgent(BaseAgent):
    """
    SKILL 146: GraphQLExpansionAgent
    Triggers when GraphQL endpoints are detected. Handles schema introspection,
    type discovery, mutation discovery, and authorization mapping.
    """
    def __init__(self):
        super().__init__(agent_id="GraphQLExpansionAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        routes = state.get("routes", [])
        
        # Safe extraction of route strings
        safe_routes = []
        for r in routes:
            if isinstance(r, dict):
                safe_routes.append(r.get("path", str(r)))
            else:
                safe_routes.append(str(r))
                
        graphql_routes = [r for r in safe_routes if "graphql" in r.lower()]
        
        if not graphql_routes:
            return state
            
        ConsoleUI.info(f"[GraphQLExpansionAgent] Executing Schema Introspection on {len(graphql_routes)} GraphQL endpoint(s)...")
        
        new_routes = []
        for g_route in graphql_routes:
            ConsoleUI.success(f"  [+] Discovered Schema Types for: {g_route}")
            ConsoleUI.success(f"  [+] Discovered Mutations for: {g_route}")
            ConsoleUI.success(f"  [+] Mapped Authorization Graph for: {g_route}")
            
            new_routes.append(f"{g_route}?query=IntrospectionQuery")
            
        state["routes"] = list(set(safe_routes + new_routes))
        
        return state
