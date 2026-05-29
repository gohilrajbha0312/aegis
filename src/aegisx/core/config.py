import os
from pathlib import Path
import getpass

class ConfigManager:
    """Manages AI API keys and other global configurations."""
    
    def __init__(self, root_dir: str = "."):
        self.env_file = Path(root_dir) / ".env"
        self.config = {}
        self._load_env()

    def _load_env(self):
        if self.env_file.exists():
            with open(self.env_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        key, val = line.split('=', 1)
                        self.config[key] = val

    def get_ai_api_key(self) -> str:
        """Retrieves the OpenRouter API Key. Prompts the user if it doesn't exist."""
        api_key = self.config.get("OPENROUTER_API_KEY")
        if not api_key:
            print("\n[AI Configuration] No OpenRouter API Key found.")
            api_key = getpass.getpass("Please enter your OpenRouter API Key: ").strip()
            if api_key:
                self.set_key("OPENROUTER_API_KEY", api_key)
            else:
                raise ValueError("OpenRouter API Key is required to run the Cognitive Orchestration Layer.")
        return api_key

    def set_key(self, key: str, value: str):
        self.config[key] = value
        with open(self.env_file, 'w') as f:
            for k, v in self.config.items():
                f.write(f"{k}={v}\n")
        # Restrict permissions
        os.chmod(self.env_file, 0o600)
