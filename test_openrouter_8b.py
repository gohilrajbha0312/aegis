import asyncio
import os
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.providers.openai import OpenAIProvider

os.environ["OPENROUTER_API_KEY"] = "your_openrouter_api_key"
os.environ["AEGIS_MODEL"] = "meta-llama/llama-3.1-8b-instruct:free"

async def main():
    try:
        provider = OpenAIProvider(
            base_url='https://openrouter.ai/api/v1',
            api_key=os.environ["OPENROUTER_API_KEY"]
        )
        model = OpenAIModel(os.environ["AEGIS_MODEL"], provider=provider)
        agent = Agent(model, system_prompt="You are a helpful assistant.")
        
        print(f"Sending request to {os.environ['AEGIS_MODEL']}...")
        result = await asyncio.wait_for(agent.run("Say 'API works!'"), timeout=15)
        print(f"Response: {result.data}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(main())
