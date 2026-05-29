import asyncio
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.agents.surgical_mutation import SurgicalMutationAgent
from aegisx.agents.traffic_analyzer import TrafficAnalyzerAgent
import os

async def main():
    state = WorkflowState(target="example.com")
    # Simulate captured requests coming from MitmProxyAdapter
    state.captured_requests = [
        "GET /api/v1/user/105/profile HTTP/1.1\nHost: example.com\nAuthorization: Bearer mock_token_105\n",
        "POST /api/v1/admin/settings HTTP/1.1\nHost: example.com\nAuthorization: Bearer mock_token_105\nContent-Type: application/json\n\n{\"role\": \"user\"}"
    ]
    
    # Run traffic analyzer
    ta = TrafficAnalyzerAgent()
    ta_res = await ta.process(state.model_dump())
    print("Traffic Analyzer Res:", ta_res)
    
    # Merge findings/state
    state.findings.extend(ta_res.get("findings", []))
    
    # Run surgical mutation
    sm = SurgicalMutationAgent()
    sm_res = await sm.process(state.model_dump())
    print("Surgical Mutation Res:", sm_res)

if __name__ == "__main__":
    asyncio.run(main())
