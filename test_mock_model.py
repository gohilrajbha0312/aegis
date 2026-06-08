import os
os.environ["GEMINI_API_KEY"] = ""

from pydantic_ai.models.test import TestModel
from pydantic_ai import Agent

model = TestModel()
agent = Agent(model, system_prompt="You are a test.")
print("Successfully instantiated mock agent!")
