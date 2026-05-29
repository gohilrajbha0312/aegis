from pydantic import BaseModel, Field
from typing import List, Optional

class Finding(BaseModel):
    id: str = Field(..., description="Unique identifier for the finding")
    title: str = Field(..., description="Short descriptive title")
    severity: str = Field(..., description="CRITICAL, HIGH, MEDIUM, LOW, INFO")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score")
    evidence: List[str] = Field(default_factory=list, description="Raw outputs or proof")
    source_tool: str = Field(..., description="Tool that generated the finding")
    cwe: Optional[str] = Field(None, description="CWE Identifier")
    cvss: Optional[float] = Field(None, description="CVSS Score")
    mitre: List[str] = Field(default_factory=list, description="MITRE ATT&CK mappings")
    affected_assets: List[str] = Field(default_factory=list, description="List of assets affected")
    exploitability: str = Field(..., description="Estimated exploitability")
    validated: bool = Field(False, description="Whether the finding has been validated")
