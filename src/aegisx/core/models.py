import os
from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.providers.openai import OpenAIProvider

# Helper to automatically read OPENROUTER_API_KEY if not in environment yet
# although it should be loaded by the orchestrator/config
def get_default_model():
    openrouter_provider = OpenAIProvider(
        base_url='https://openrouter.ai/api/v1',
        api_key=os.getenv("OPENROUTER_API_KEY", "dummy")
    )
    return OpenAIModel(os.getenv('AEGIS_MODEL', 'openrouter/free'), provider=openrouter_provider)

default_model = get_default_model()
