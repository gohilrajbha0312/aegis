import asyncio
import os
import sys
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic import BaseModel

class OutputSchema(BaseModel):
    is_success: bool
    message: str

os.environ["OPENROUTER_API_KEY"] = "your_openrouter_api_key"

models_to_test = [
    "poolside/laguna-xs.2:free",
    "moonshotai/kimi-k2.6:free",
    "liquid/lfm-2.5-1.2b-instruct:free",
    "openai/gpt-oss-120b:free",
    "qwen/qwen3-next-80b-a3b-instruct:free",
    "z-ai/glm-4.5-air:free",
    "cognitivecomputations/dolphin-mistral-24b-venice-edition:free"
]

async def test_model(model_name):
    try:
        provider = OpenAIProvider(base_url='https://openrouter.ai/api/v1', api_key=os.environ["OPENROUTER_API_KEY"])
        model = OpenAIModel(model_name, provider=provider)
        agent = Agent(model, system_prompt="You are a helpful assistant.", output_type=OutputSchema)
        
        print(f"\n--- Testing {model_name} ---")
        result = await asyncio.wait_for(agent.run("Say 'API works!' and return success=true"), timeout=15)
        print(f"SUCCESS! Response: {result.data}")
        return True
    except asyncio.TimeoutError:
        print("TIMEOUT")
    except Exception as e:
        print(f"ERROR: {e}")
    return False

async def main():
    for m in models_to_test:
        await test_model(m)

if __name__ == "__main__":
    asyncio.run(main())
