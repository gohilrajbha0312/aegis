import hashlib
import hmac
import json
import time
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class EvidenceArtifact(BaseModel):
    artifact_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    workflow_id: str
    timestamp: float = Field(default_factory=time.time)
    content: Dict[str, Any]
    content_hash: str = ""
    parent_hash: Optional[str] = None
    signature: str = ""

class ForensicEvidenceChain:
    """
    Immutable, append-only evidence chain using HMAC signing and SHA-256.
    """
    def __init__(self, hmac_secret: bytes):
        self._hmac_secret = hmac_secret
        self._chain: List[EvidenceArtifact] = []
        self._latest_hash: Optional[str] = None

    def _hash_content(self, content: Dict[str, Any]) -> str:
        content_str = json.dumps(content, sort_keys=True)
        return hashlib.sha256(content_str.encode('utf-8')).hexdigest()

    def _sign_artifact(self, artifact_hash: str) -> str:
        return hmac.new(
            self._hmac_secret, 
            artifact_hash.encode('utf-8'), 
            hashlib.sha256
        ).hexdigest()

    def capture_evidence(self, workflow_id: str, content: Dict[str, Any]) -> EvidenceArtifact:
        """Capture and cryptographically sign new evidence."""
        artifact = EvidenceArtifact(
            workflow_id=workflow_id,
            content=content,
            parent_hash=self._latest_hash
        )
        
        # Calculate content hash
        artifact.content_hash = self._hash_content(content)
        
        # Calculate signature including parent hash to enforce chain integrity
        chain_link = f"{artifact.content_hash}:{artifact.parent_hash or ''}"
        artifact.signature = self._sign_artifact(chain_link)
        
        self._chain.append(artifact)
        self._latest_hash = artifact.content_hash
        
        return artifact

    def verify_chain(self) -> bool:
        """Verify the integrity of the entire evidence chain."""
        expected_parent_hash = None
        for artifact in self._chain:
            # Check linkage
            if artifact.parent_hash != expected_parent_hash:
                return False
                
            # Check content hash
            actual_content_hash = self._hash_content(artifact.content)
            if actual_content_hash != artifact.content_hash:
                return False
                
            # Check signature
            chain_link = f"{artifact.content_hash}:{artifact.parent_hash or ''}"
            expected_signature = self._sign_artifact(chain_link)
            if artifact.signature != expected_signature:
                return False
                
            expected_parent_hash = artifact.content_hash
            
        return True

    def flush_to_disk(self, filepath: str) -> None:
        """Append the chain to an audit log file."""
        # In a real system, this should use append mode securely, 
        # potentially with remote centralized logging (like WORM storage)
        with open(filepath, 'a') as f:
            for artifact in self._chain:
                f.write(artifact.model_dump_json() + '\n')
        
        # Clear local memory cache if we are only an append-only bridge
        # self._chain = [] 
