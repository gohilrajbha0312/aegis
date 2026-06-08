import os
os.environ["GEMINI_API_KEY"] = "dummy_key"
from pydantic_ai.models.gemini import GeminiModel

model = GeminiModel("gemini-2.0-flash")
print("Successfully instantiated!")
