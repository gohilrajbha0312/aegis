import os
from typing import List, Dict, Any

try:
    import chromadb
    _CHROMA_AVAILABLE = True
except ImportError:
    _CHROMA_AVAILABLE = False

class AgentMemoryStore:
    """
    RAG Context Engine using ChromaDB.
    Provides historical context and policy information to the AI agents to prevent hallucinations.
    Degrades gracefully if chromadb is not installed.
    """
    def __init__(self, persist_directory: str = "/tmp/aegisx_memory"):
        self.persist_directory = persist_directory
        self.client = None
        self.history_collection = None
        self.policy_collection = None

        if not _CHROMA_AVAILABLE:
            return

        self.client = chromadb.PersistentClient(path=self.persist_directory)
        self.history_collection = self.client.get_or_create_collection(name="aegisx_history")
        self.policy_collection = self.client.get_or_create_collection(name="aegisx_policies")
        self._seed_default_policies()

    def _seed_default_policies(self):
        """Injects default RAG context so the AI knows what to look for."""
        if not _CHROMA_AVAILABLE or self.policy_collection is None:
            return

        policies = [
            "Port 3000/9090 are typically observability stacks. If unauthenticated, it's a MEDIUM risk.",
            "Any route containing /admin/ without an authentication boundary is a CRITICAL risk.",
            "Cloud Metadata endpoints (169.254.169.254) are CRITICAL if accessible via SSRF.",
            "GraphQL introspection enabled in production is a HIGH risk.",
            "Missing Security Headers are a LOW risk, PASSIVE_ANALYSIS only."
        ]

        if self.policy_collection.count() == 0:
            for i, doc in enumerate(policies):
                self.policy_collection.add(
                    documents=[doc],
                    metadatas=[{"type": "governance_policy"}],
                    ids=[f"policy_{i}"]
                )

    def query_policy(self, query: str, n_results: int = 2) -> List[str]:
        """Allows an Agent to query the policy database."""
        if not _CHROMA_AVAILABLE or self.policy_collection is None:
            return []

        results = self.policy_collection.query(
            query_texts=[query],
            n_results=n_results
        )
        if results and "documents" in results and results["documents"]:
            return results["documents"][0]
        return []

    def record_finding_feedback(self, finding_id: str, context: str, approved: bool):
        """Records whether a finding was approved by a human to train future priors."""
        if not _CHROMA_AVAILABLE or self.history_collection is None:
            return

        self.history_collection.add(
            documents=[context],
            metadatas=[{"finding_id": finding_id, "approved": approved}],
            ids=[finding_id]
        )

    def query_history(self, context_query: str, n_results: int = 2) -> List[Dict[str, Any]]:
        """Queries historical analyst feedback to adjust Bayesian priors."""
        if not _CHROMA_AVAILABLE or self.history_collection is None:
            return []

        results = self.history_collection.query(
            query_texts=[context_query],
            n_results=n_results
        )

        history = []
        if results and "documents" in results and "metadatas" in results:
            for i in range(len(results["documents"][0])):
                history.append({
                    "context": results["documents"][0][i],
                    "approved": results["metadatas"][0][i]["approved"]
                })
        return history
