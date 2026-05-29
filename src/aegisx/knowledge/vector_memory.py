import chromadb
from chromadb.config import Settings
import json
from typing import List, Dict, Any
import os

class VectorMemory:
    """Runtime AI Memory using ChromaDB to store and retrieve historical findings."""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(VectorMemory, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance
        
    def _initialize(self):
        persist_dir = os.path.join(os.getcwd(), ".chroma")
        self.client = chromadb.PersistentClient(path=persist_dir)
        self.collection = self.client.get_or_create_collection(name="aegisx_memory")
        
    def store_finding(self, target: str, finding_id: str, title: str, severity: str, details: str):
        """Store a finding in the vector database."""
        document = f"[{severity}] {title} - {details}"
        metadata = {"target": target, "severity": severity}
        
        self.collection.upsert(
            documents=[document],
            metadatas=[metadata],
            ids=[finding_id]
        )
        
    def retrieve_context(self, target: str, query: str = "vulnerability", n_results: int = 3) -> List[str]:
        """Retrieve historical context for a target based on semantic similarity."""
        try:
            results = self.collection.query(
                query_texts=[f"{target} {query}"],
                n_results=n_results,
                where={"target": target}
            )
            if results and results['documents'] and results['documents'][0]:
                return results['documents'][0]
        except Exception:
            pass
        return []
