from aegisx.core.models import default_model
from typing import Dict, Any
from aegisx.agents.base import BaseAgent
from aegisx.core.schemas.findings import Finding
import uuid
import json
from pydantic_ai import Agent

# In a real implementation this would use Playwright to actually fetch DOMs
# Here we simulate the AI analyzing a provided DOM state
dom_analyzer_ai = Agent(
    default_model,
    system_prompt="You are a Web Crawler & DOM Analysis Agent. Analyze the provided HTML/DOM state for DOM-based XSS or business logic flaws."
)

class WebCrawlerAgent(BaseAgent):
    """
    Agent for deep stateful web crawling and DOM analysis.
    """
    
    def __init__(self):
        super().__init__(agent_id="WebCrawlerAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        target = state.get("target")
        self.log_action("start_web_crawl", {"target": target})
        
        # Simulated Playwright output analysis
        # In reality, this agent would orchestrate playwright.async_api
        findings = []
        html_state = state.get("dom_state", "<html><script>eval(location.hash.slice(1))</script></html>")
        
        result = await dom_analyzer_ai.run(f"Analyze this DOM for vulnerabilities:\n{html_state}")
        analysis = result.output
        
        if "eval" in html_state and "location" in html_state:
            finding = Finding(
                id=str(uuid.uuid4()),
                title="DOM-Based XSS Discovered",
                severity="HIGH",
                confidence=0.9,
                evidence=[f"Vulnerable Sink: {html_state}", f"AI Analysis: {analysis[:100]}"],
                source_tool="WebCrawlerAgent",
                cwe="CWE-79",
                affected_assets=[target],
                exploitability="High"
            )
            findings.append(finding)
            
        self.log_action("web_crawl_complete", {"findings_count": len(findings)})
        return {"phase": "web_crawl_complete", "findings": findings}
