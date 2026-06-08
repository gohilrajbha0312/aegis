import os
from typing import Dict, Any, List
from pydantic import BaseModel
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.providers.openai import OpenAIProvider
from aegisx.core.ui.console import ConsoleUI

class ModelHealthStatus(BaseModel):
    status: str # "online|degraded|offline"
    latency_ms: float
    quota_remaining: int
    context_usage: int

class OpenRouterFailoverAgent:
    """
    SKILL 77: OpenRouterFailoverAgent
    Maintains a model pool and automatically switches models upon failure.
    """
    def __init__(self):
        self.model_pool = [
            "openai/gpt-oss-20b:free"
        ]
        # De-duplicate pool
        seen = set()
        self.model_pool = [x for x in self.model_pool if not (x in seen or seen.add(x))]
        
        self.current_index = 0
        self.api_key = os.getenv("OPENROUTER_API_KEY", "")
        self.base_url = 'https://openrouter.ai/api/v1'
        self.current_model_name = self.model_pool[self.current_index]

    def get_current_model(self) -> OpenAIModel:
        provider = OpenAIProvider(base_url=self.base_url, api_key=self.api_key)
        return OpenAIModel(self.current_model_name, provider=provider)

    def switch_model(self) -> bool:
        if self.current_index >= len(self.model_pool) - 1:
            ConsoleUI.error("[FailoverAgent] Model pool exhausted. All fallback models failed.")
            return False
            
        self.current_index += 1
        self.current_model_name = self.model_pool[self.current_index]
        ConsoleUI.warning(f"[FailoverAgent] Switched to fallback model: {self.current_model_name}")
        return True
        
    def build_agent(self, prompt: str, output_type: type) -> Agent:
        return Agent(self.get_current_model(), output_type=output_type, system_prompt=prompt)


class ModelHealthAgent:
    """
    SKILL 76: ModelHealthAgent
    Monitors model health and triggers failover.
    """
    def __init__(self):
        self.failover = OpenRouterFailoverAgent()
        
    def check_health(self, error_str: str) -> ModelHealthStatus:
        status = "online"
        err = error_str.lower()
        if "429" in err or "timeout" in err or "quota" in err or "rate limit" in err:
            status = "offline"
            
        return ModelHealthStatus(
            status=status,
            latency_ms=0.0,
            quota_remaining=0,
            context_usage=0
        )
        
    def handle_failure(self, error_str: str) -> bool:
        """
        Evaluates an error and triggers failover if necessary.
        Returns True if a failover occurred and it's safe to retry, False if pool exhausted.
        """
        health = self.check_health(error_str)
        if health.status == "offline":
            ConsoleUI.warning(f"[ModelHealthAgent] Detected model degradation/failure: {error_str[:100]}")
            return self.failover.switch_model()
        return False

# Global health engine singleton
model_health_engine = ModelHealthAgent()
