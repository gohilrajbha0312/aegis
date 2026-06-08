from aegisx.core.models import default_model
import os
from typing import List, Dict, Any, TypedDict

try:
    from google import genai
    _GENAI_AVAILABLE = True
except ImportError:
    _GENAI_AVAILABLE = False

try:
    from langgraph.graph import StateGraph, END
    _LANGGRAPH_AVAILABLE = True
except ImportError:
    _LANGGRAPH_AVAILABLE = False

from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.agents.schemas import CognitiveFinding, AgentConsensusVote, AIHypothesis, AttackNode, AttackEdge
from aegisx.core.agents.memory import AgentMemoryStore
from aegisx.core.ui.console import ConsoleUI
from aegisx.core.orchestration.command_gateway import CommandGateway

# Define the State for our LangGraph AI Workflow
class AgentState(TypedDict):
    evidence_blob: str
    recon_vote: AgentConsensusVote
    vuln_vote: AgentConsensusVote
    governance_decision: str
    final_hypothesis: AIHypothesis
    conflict_detected: bool

class LangGraphReasoningEngine:
    """
    Advanced Multi-Agent Reasoning Engine.
    Uses LangGraph for cyclical workflow and Instructor for structured outputs.
    """
    def __init__(self, use_mock: bool = False):
        self.use_mock = use_mock
        self.memory = AgentMemoryStore()
        
        api_key = os.getenv("GEMINI_API_KEY")
        
        if self.use_mock or not _GENAI_AVAILABLE or not api_key:
            self.client = None
            if not self.use_mock:
                ConsoleUI.warning("Missing GEMINI_API_KEY or google-genai, falling back to mock.")
                self.use_mock = True
        else:
            try:
                self.client = genai.Client(api_key=api_key)
            except Exception as e:
                ConsoleUI.warning(f"Failed to initialize google-genai client: {e}. Falling back to mock.")
                self.use_mock = True

    def build_graph(self):
        """Constructs the Multi-Agent state graph, or returns None if LangGraph unavailable."""
        if not _LANGGRAPH_AVAILABLE:
            return None
            
        workflow = StateGraph(AgentState)

        # Add Nodes
        workflow.add_node("recon_agent", self._node_recon_agent)
        workflow.add_node("vuln_agent", self._node_vuln_agent)
        workflow.add_node("consensus_engine", self._node_consensus)
        workflow.add_node("graph_architect", self._node_graph_architect)

        # Build Edges
        # Evidence goes to both Recon and Vuln agents (parallel conceptually, but sequential in simple graph)
        workflow.set_entry_point("recon_agent")
        workflow.add_edge("recon_agent", "vuln_agent")
        workflow.add_edge("vuln_agent", "consensus_engine")
        
        # Conditional Edge based on conflict
        workflow.add_conditional_edges(
            "consensus_engine",
            self._route_consensus,
            {
                "conflict": END, # Pause for HITL if conflict
                "agreed": "graph_architect"
            }
        )
        
        workflow.add_edge("graph_architect", END)
        
        return workflow.compile()

    # --- Nodes ---

    def _node_recon_agent(self, state: AgentState) -> AgentState:
        ConsoleUI.stream_line("[LangGraph] ReconAgent analyzing evidence...")
        if self.use_mock:
            state["recon_vote"] = AgentConsensusVote(
                agent_id="ReconAgent", target_finding_id="f1", vote_confidence=0.85, reasoning="Found port 3000."
            )
            return state

        # Real LLM Call with Instructor
        context = self.memory.query_policy("What are the risks of the discovered ports?", n_results=1)
        prompt = f"Analyze this recon data and determine exposure confidence. Policy context: {context}. Evidence: {state['evidence_blob']}"
        
        try:
            response = self.client.models.generate_content(
                model=default_model,
                contents=prompt,
                config=genai.types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=AgentConsensusVote,
                    temperature=0.1
                )
            )
            state["recon_vote"] = response.parsed
        except Exception:
            state["recon_vote"] = AgentConsensusVote(agent_id="ReconAgent", target_finding_id="f1", vote_confidence=0.5, reasoning="Error querying LLM.")
            
        return state

    def _node_vuln_agent(self, state: AgentState) -> AgentState:
        ConsoleUI.stream_line("[LangGraph] VulnAgent analyzing evidence...")
        if self.use_mock:
            state["vuln_vote"] = AgentConsensusVote(
                agent_id="VulnAgent", target_finding_id="f1", vote_confidence=0.80, reasoning="Likely observability exposure."
            )
            return state

        context = self.memory.query_policy("What are the standard vulnerabilities associated with this evidence?", n_results=1)
        prompt = f"Analyze this recon data for CVEs and weaknesses. Policy context: {context}. Evidence: {state['evidence_blob']}"
        
        try:
            def execute_targeted_scan(tool_name: str, target_url: str, extra_args: str = "") -> str:
                """Execute a specific active scan (e.g. sqlmap, nuclei) against a specific endpoint to confirm a vulnerability hypothesis."""
                ConsoleUI.info(f"[AI Tool Execution] VulnAgent dynamically triggered: {tool_name} against {target_url}")
                cmd = []
                if tool_name == "sqlmap":
                    cmd = ["sqlmap", "-u", target_url, "--batch", "--random-agent", "--level", "1"]
                elif tool_name == "nuclei":
                    cmd = ["nuclei", "-u", target_url, "-silent"]
                    
                if extra_args:
                    cmd.extend(extra_args.split(" "))
                    
                if cmd:
                    res = CommandGateway.execute(cmd, timeout=120, description=f"AI Targeted {tool_name} Scan")
                    return res.get("stdout", "")[:1000]
                return "Unknown tool"

            def execute_web_vuln_scan(vuln_type: str, target_url: str) -> str:
                """Execute targeted web vulnerability scans (e.g. Brute Force, CSRF, SQLi, XSS, File Inclusion/Upload, CSP Bypass, DIR_DISCOVERY)."""
                ConsoleUI.info(f"[AI Tool Execution] VulnAgent probing specifically for {vuln_type} at {target_url}")
                cmd = []
                description = ""
                
                if vuln_type in ["SQLI", "SQLI_BLIND"]:
                    cmd = ["sqlmap", "-u", target_url, "--batch", "--risk", "2"]
                    description = "SQLi Scan"
                elif vuln_type == "BRUTE_FORCE":
                    cmd = ["hydra", "-l", "admin", "-p", "admin", target_url, "http-get"]
                    description = "Brute Force Scan"
                elif vuln_type in ["XSS", "DOM_XSS", "REFLECTED_XSS", "STORED_XSS", "JS_WEAKNESS"]:
                    cmd = ["nuclei", "-u", target_url, "-tags", "xss", "-silent"]
                    description = "XSS Scan"
                elif vuln_type in ["LFI", "PATH_TRAVERSAL", "FILE_UPLOAD"]:
                    cmd = ["nuclei", "-u", target_url, "-tags", "lfi,rfi,upload", "-silent"]
                    description = "File Handling Scan"
                elif vuln_type in ["CSRF", "CSP_BYPASS", "OPEN_REDIRECT"]:
                    cmd = ["nuclei", "-u", target_url, "-tags", "misconfig", "-silent"]
                    description = "Web Config Scan"
                elif vuln_type in ["DIR_DISCOVERY", "FUZZING", "HIDDEN_FILE_DISCOVERY"]:
                    # Ensure url has trailing slash for FFUF if it doesn't have FUZZ yet
                    fuzz_url = target_url if "FUZZ" in target_url else target_url.rstrip('/') + "/FUZZ"
                    cmd = ["ffuf", "-u", fuzz_url, "-w", "wordlists/common.txt", "-mc", "200,204,301,302,307,401,403,405,500"]
                    description = "Directory & Route Fuzzing"
                else:
                    cmd = ["nuclei", "-u", target_url, "-tags", "cve,vuln", "-silent"]
                    description = f"Generic Web Scan for {vuln_type}"
                    
                if cmd:
                    res = CommandGateway.execute(cmd, timeout=120, description=f"AI Web Vuln {description}")
                    return res.get("stdout", "")[:1500]
                return "Unknown vuln_type"

            # Use google-genai Chats for automatic function calling loop
            chat = self.client.chats.create(
                model=default_model,
                config=genai.types.GenerateContentConfig(
                    tools=[execute_targeted_scan, execute_web_vuln_scan],
                    temperature=0.2
                )
            )
            chat.send_message(prompt)
            
            # Ask it to summarize into the structured JSON vote
            final_response = chat.send_message(
                "Based on the evidence and any tool results you just ran, provide your final consensus vote.",
                config=genai.types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=AgentConsensusVote,
                    temperature=0.1
                )
            )
            
            state["vuln_vote"] = final_response.parsed
            
        except Exception as e:
            ConsoleUI.warning(f"Error in VulnAgent: {e}")
            state["vuln_vote"] = AgentConsensusVote(agent_id="VulnAgent", target_finding_id="f1", vote_confidence=0.5, reasoning="Error querying LLM.")
            
        return state

    def _node_consensus(self, state: AgentState) -> AgentState:
        ConsoleUI.stream_line("[LangGraph] Consensus Engine calculating Delta...")
        delta = abs(state["recon_vote"].vote_confidence - state["vuln_vote"].vote_confidence)
        
        if delta > 0.30:
            ConsoleUI.warning(f"AI CONFLICT DETECTED (Delta: {delta:.2f}). Escalating to Human Operator.")
            state["conflict_detected"] = True
        else:
            state["conflict_detected"] = False
            
        return state

    def _route_consensus(self, state: AgentState) -> str:
        if state.get("conflict_detected", False):
            return "conflict"
        return "agreed"

    def _node_graph_architect(self, state: AgentState) -> AgentState:
        ConsoleUI.stream_line("[LangGraph] GraphArchitect generating nodes/edges...")
        if self.use_mock:
            state["final_hypothesis"] = AIHypothesis(
                hypothesis="Observability Exposure",
                confidence=(state["recon_vote"].vote_confidence + state["vuln_vote"].vote_confidence) / 2,
                reasoning=[state["recon_vote"].reasoning, state["vuln_vote"].reasoning],
                validation_required=True,
                nodes=[AttackNode(node_id="n1", node_type="SERVICE", properties={"port": "3000"})],
                edges=[]
            )
            return state

        # Real LLM Call for Graph Structuring
        prompt = f"Given these agent votes:\nRecon: {state['recon_vote'].model_dump_json()}\nVuln: {state['vuln_vote'].model_dump_json()}\nGenerate an Attack Graph Hypothesis."
        try:
            response = self.client.models.generate_content(
                model=default_model,
                contents=prompt,
                config=genai.types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=AIHypothesis,
                    temperature=0.1
                )
            )
            state["final_hypothesis"] = response.parsed
        except Exception:
            state["final_hypothesis"] = AIHypothesis(hypothesis="Fallback", confidence=0.0, reasoning=[], validation_required=False)
            
        return state

    def generate_hypotheses(self, workflow_state: WorkflowState) -> List[AIHypothesis]:
        """
        Extracts evidence from the DAG state and executes the LangGraph workflow.
        """
        # The AI will now attempt to use the provided OPENAI_API_KEY.
        # If it's missing or invalid, LangGraph will fail during invocation.
        context_blob = f"Target: {workflow_state.normalized_target}\nEvidence:\n"
        for item in workflow_state.evidence_ledger:
            context_blob += f"- [{item['stage']}] {item['action']}: {item.get('result', '')}\n"

        app = self.build_graph()

        # If LangGraph is not installed or mock mode, return deterministic mock hypotheses
        if app is None or self.use_mock:
            ConsoleUI.stream_line("[LangGraph] Running in MOCK mode (no API key / LangGraph unavailable).")
            port = workflow_state.normalized_target.split(":")[-1] if ":" in workflow_state.normalized_target else "80"
            confidence = 0.85 if port in ["3000", "9090", "9091"] else 0.42
            return [
                AIHypothesis(
                    hypothesis="Observability Leakage Path" if port in ["3000", "9090"] else "Generic Exposure Path",
                    confidence=confidence,
                    reasoning=[
                        f"Port {port} detected. Correlated with monitoring stack signature.",
                        "If unauthenticated, exposes infrastructure metadata.",
                    ],
                    validation_required=True,
                    nodes=[AttackNode(node_id="n1", node_type="SERVICE", properties={"port": port})],
                    edges=[]
                )
            ]
        
        initial_state: AgentState = {
            "evidence_blob": context_blob,
            "recon_vote": AgentConsensusVote(agent_id="", target_finding_id="", vote_confidence=0.0, reasoning=""),
            "vuln_vote": AgentConsensusVote(agent_id="", target_finding_id="", vote_confidence=0.0, reasoning=""),
            "governance_decision": "",
            "final_hypothesis": AIHypothesis(hypothesis="", confidence=0.0, reasoning=[]),
            "conflict_detected": False
        }
        
        final_state = app.invoke(initial_state)
        
        if final_state.get("conflict_detected"):
            ConsoleUI.warning("AI CONFLICT DETECTED. Returning empty hypotheses — escalate to HITL.")
            return []
            
        if "final_hypothesis" in final_state and final_state["final_hypothesis"].hypothesis:
            return [final_state["final_hypothesis"]]
            
        return []

# Backward-compatible alias so that existing stage_consensus.py imports still work.
AIReasoningEngine = LangGraphReasoningEngine

