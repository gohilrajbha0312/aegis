from abc import ABC, abstractmethod
from typing import Dict, Any, List
from aegisx.core.schemas.findings import Finding

class BaseAgent(ABC):
    """
    Abstract Base Class for all AEGIS-X Cognitive Agents.
    Forces all agents to maintain isolated context memory and stream telemetry.
    """
    
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.memory = []
        
    def log_action(self, action: str, details: Dict[str, Any]):
        """Append an action to the agent's isolated memory context."""
        self.memory.append({"action": action, "details": details})
        
    @abstractmethod
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        The core reasoning loop for the agent.
        Takes the global workflow state and returns updates (findings, commands).
        """
        pass
