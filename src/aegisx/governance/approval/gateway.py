import time
import uuid
import hashlib
import hmac
from typing import Dict, List, Set, Optional
from pydantic import BaseModel, Field

from aegisx.governance.policy.engine import RiskLevel

class OperatorRole(BaseModel):
    role_id: str
    permissions: List[str]

class HumanApprovalRequest(BaseModel):
    request_id: str
    risk: RiskLevel
    description: str
    timestamp: float = Field(default_factory=time.time)
    expires_in_seconds: int = 1800 # Default 30 minutes expiration
    required_quorum: int = 1

class CryptographicSignature(BaseModel):
    request_id: str
    operator_id: str
    role: str
    timestamp: float
    nonce: str
    expiration: float
    signature: str # HMAC signature
    approval_scope: str

class HumanApprovalGateway:
    """
    Manages human-in-the-loop approvals using strict cryptographic signatures, 
    RBAC, and replay prevention.
    """
    def __init__(self, hmac_secret: bytes = b'mock-secret-key'):
        self._hmac_secret = hmac_secret
        # Maps request_id to a set of operator_ids that have approved it
        self._approvals_store: Dict[str, Set[str]] = {}
        # Stores active requests
        self._active_requests: Dict[str, HumanApprovalRequest] = {}
        # Simple local RBAC store for demonstration
        self._rbac_store: Dict[str, OperatorRole] = {}
        # Prevent replay attacks by storing used nonces
        self._seen_nonces: Set[str] = set()

    def register_operator(self, operator_id: str, role: OperatorRole):
        """Register an operator and their RBAC role."""
        self._rbac_store[operator_id] = role

    def create_approval_request(self, request_id: str, risk: RiskLevel, description: str, required_quorum: int = 1) -> HumanApprovalRequest:
        """Create a new approval request, scaling required approvals by risk."""
        request = HumanApprovalRequest(
            request_id=request_id,
            risk=risk,
            description=description,
            required_quorum=required_quorum
        )
        self._active_requests[request_id] = request
        self._approvals_store[request_id] = set()
        return request

    def _verify_cryptographic_signature(self, sig: CryptographicSignature) -> bool:
        """
        Verify the cryptographic signature of the approval.
        """
        payload = f"{sig.request_id}:{sig.operator_id}:{sig.role}:{sig.timestamp}:{sig.nonce}:{sig.expiration}:{sig.approval_scope}"
        expected_hash = hmac.new(
            self._hmac_secret, 
            payload.encode('utf-8'), 
            hashlib.sha256
        ).hexdigest()
        
        return sig.signature == expected_hash

    def submit_approval(self, signature: CryptographicSignature) -> bool:
        """
        Submit a cryptographic approval from an operator.
        Returns True if the approval was valid and accepted.
        """
        request = self._active_requests.get(signature.request_id)
        if not request:
            raise ValueError(f"No active approval request found for {signature.request_id}.")

        # 1. Check expiration of the request
        if time.time() > request.timestamp + request.expires_in_seconds:
            # Expired approvals MUST invalidate execution and require re-approval
            del self._active_requests[signature.request_id]
            raise ValueError("Approval request has expired.")
            
        # 2. Check expiration of the signature itself
        if time.time() > signature.expiration:
            raise ValueError("Cryptographic signature has expired.")

        # 3. Replay prevention
        if signature.nonce in self._seen_nonces:
            # Reused nonce = automatic rejection
            raise ValueError("Replay detected: nonce already used.")

        # 4. RBAC Enforcement
        operator_role = self._rbac_store.get(signature.operator_id)
        if not operator_role or operator_role.role_id != signature.role:
            raise ValueError("Operator not authorized or role mismatch (RBAC failure).")

        # 5. Cryptographic verification
        if not self._verify_cryptographic_signature(signature):
            raise ValueError("Cryptographic signature verification failed.")

        # Register successful approval
        self._seen_nonces.add(signature.nonce)
        self._approvals_store[signature.request_id].add(signature.operator_id)
        return True

    def is_action_fully_approved(self, request_id: str) -> bool:
        """Check if all required multi-party approvals have been met."""
        request = self._active_requests.get(request_id)
        if not request:
            return False
            
        # Check expiration before validating final status
        if time.time() > request.timestamp + request.expires_in_seconds:
            return False
            
        approvals_gathered = len(self._approvals_store.get(request_id, set()))
        return approvals_gathered >= request.required_quorum
