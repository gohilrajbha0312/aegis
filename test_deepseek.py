import asyncio
import os
from pydantic_ai import Agent

def load_env():
    with open('/home/kali/Projects/aegisx/.env', 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                k, v = line.split('=', 1)
                os.environ[k] = v

load_env()

from aegisx.core.models import get_default_model
from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.providers.openai import OpenAIProvider

openrouter_provider = OpenAIProvider(
    base_url='https://openrouter.ai/api/v1',
    api_key=os.getenv("OPENROUTER_API_KEY_2", "dummy")
)
default_model = OpenAIModel('deepseek/deepseek-chat:free', provider=openrouter_provider)

async def main():
    print(f"Using API KEY: {os.getenv('OPENROUTER_API_KEY_2')}")
    agent = Agent(default_model, system_prompt="You are a helpful assistant.")
    try:
        result = await agent.run("Hello, are you working?")
        print(f"SUCCESS: {result.data}")
    except Exception as e:
        print(f"FAILED: {e}")

if __name__ == "__main__":
    asyncio.run(main())
