from abc import ABC, abstractmethod
from typing import Dict, Any

class ToolAdapter(ABC):
    """
    Abstract base class for all enterprise vulnerability scanners and recon tools.
    Never hardcode tool execution; implement this interface to ensure telemetry,
    sandbox isolation, and strict result normalization.
    """

    @abstractmethod
    async def execute(self, operation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes the tool asynchronously.
        
        Args:
            operation: Context dictionary containing target, wordlists, config.
            
        Returns:
            Normalized results mapping to the Finding schema.
        """
        pass
