import os
import argparse
from aegisx.core.taxonomy.vulnerability_taxonomy import GovernanceClass
from aegisx.governance.policy.engine import GovernancePolicyEngine, GovernanceActionRequest, RiskLevel
from aegisx.governance.approval.gateway import HumanApprovalGateway, OperatorRole, CryptographicSignature, HumanApprovalRequest

def run_example(target: str):
    print(f"--- AEGIS-X Phase 1 Example (Target: {target}) ---")
    
    # 1. Setup Policy Engine
    policy_engine = GovernancePolicyEngine()
    
    # Let's test a low-risk passive scan
    passive_request = GovernanceActionRequest(
        action_id="scan-123",
        risk=RiskLevel.LOW,
        governance_class=GovernanceClass.PASSIVE_ANALYSIS,
        operator_signoff_required=False,
        details={"target": target}
    )
    
    decision1 = policy_engine.evaluate_request(passive_request)
    print(f"\n[Passive Scan Decision] Approved: {decision1.approved}, Reason: {decision1.reason}")
    
    # Let's test an intrusive validation scan
    intrusive_request = GovernanceActionRequest(
        action_id="exploit-test-456",
        risk=RiskLevel.HIGH,
        governance_class=GovernanceClass.INTRUSIVE_VALIDATION,
        operator_signoff_required=True,
        details={"target": target, "payload": "safe_sleep"}
    )
    
    decision2 = policy_engine.evaluate_request(intrusive_request)
    print(f"\n[Intrusive Scan Decision] Approved: {decision2.approved}, Reason: {decision2.reason}")
    
    # 2. Setup Approval Gateway since intrusive scan requires human approval
    gateway = HumanApprovalGateway()
    
    # Register an operator
    gateway.register_operator("op-alice", OperatorRole(role_id="admin", permissions=["approve_all"]))
    gateway.register_operator("op-bob", OperatorRole(role_id="admin", permissions=["approve_all"]))
    
    print("\n--- Requesting Human Approval ---")
    approval_request = gateway.create_approval_request(
        action_id="exploit-test-456", 
        risk=RiskLevel.HIGH, 
        description=f"High risk intrusive validation against {target}"
    )
    print(f"Request created. Requires {approval_request.required_approvals} approvals.")
    
    # Create mock cryptographic signatures for Alice and Bob
    # In a real system, this would be a PKI signed hash
    import time
    import hashlib
    
    def mock_sign(action_id, op_id, nonce):
        timestamp = time.time()
        payload = f"{action_id}:{op_id}:{nonce}:{timestamp}"
        return CryptographicSignature(
            operator_id=op_id,
            nonce=nonce,
            timestamp=timestamp,
            signature_hash=hashlib.sha256(payload.encode('utf-8')).hexdigest()
        )
        
    alice_sig = mock_sign("exploit-test-456", "op-alice", "nonce-1")
    bob_sig = mock_sign("exploit-test-456", "op-bob", "nonce-2")
    
    # Submit approvals
    gateway.submit_approval("exploit-test-456", alice_sig)
    print(f"Alice approved. Fully approved? {gateway.is_action_fully_approved('exploit-test-456')}")
    
    gateway.submit_approval("exploit-test-456", bob_sig)
    print(f"Bob approved. Fully approved? {gateway.is_action_fully_approved('exploit-test-456')}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AEGIS-X Governance Example")
    parser.add_argument("-t", "--target", type=str, default="10.0.0.5", help="The target IP or hostname to scan")
    args = parser.parse_args()
    
    run_example(args.target)
