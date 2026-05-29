import os
from pydantic_ai import Agent, RunContext
from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.providers.openai import OpenAIProvider
import asyncio

async def main():
    with open(".env", "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                k, v = line.split('=', 1)
                os.environ[k] = v

    provider = OpenAIProvider(
        base_url='https://openrouter.ai/api/v1',
        api_key=os.environ.get("OPENROUTER_API_KEY_2", "dummy")
    )
    
    # Try Deepseek
    model_2 = OpenAIModel('deepseek/deepseek-v4-flash:free', provider=provider)
    ai_2 = Agent(model_2, system_prompt="Say hi")
    
    try:
        res = await ai_2.run("hello")
        print("DeepSeek success:", res.data)
    except Exception as e:
        print("DeepSeek failed:", e)

    # Try Llama
    provider3 = OpenAIProvider(
        base_url='https://openrouter.ai/api/v1',
        api_key=os.environ.get("OPENROUTER_API_KEY_3", "dummy")
    )
    model_3 = OpenAIModel('meta-llama/llama-3.3-70b-instruct:free', provider=provider3)
    ai_3 = Agent(model_3, system_prompt="Say hi")
    
    try:
        res = await ai_3.run("hello")
        print("Llama success:", res.data)
    except Exception as e:
        print("Llama failed:", e)

if __name__ == "__main__":
    asyncio.run(main())
