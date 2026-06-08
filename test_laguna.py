import asyncio
import os
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic import BaseModel

class OutputSchema(BaseModel):
    is_success: bool
    message: str

os.environ["OPENROUTER_API_KEY"] = "your_openrouter_api_key"
os.environ["AEGIS_MODEL"] = "poolside/laguna-xs.2:free"

async def main():
    try:
        provider = OpenAIProvider(
            base_url='https://openrouter.ai/api/v1',
            api_key=os.environ["OPENROUTER_API_KEY"]
        )
        model = OpenAIModel(os.environ["AEGIS_MODEL"], provider=provider)
        agent = Agent(model, system_prompt="You are a helpful assistant.", output_type=OutputSchema)
        
        result = await asyncio.wait_for(agent.run("Say 'API works!' and return success=true"), timeout=15)
        print("SUCCESS")
        print(dir(result))
    except Exception as e:
        print(f"Error: {e.__class__.__name__} - {e}")

if __name__ == "__main__":
    asyncio.run(main())
