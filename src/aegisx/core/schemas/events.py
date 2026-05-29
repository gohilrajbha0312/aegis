from pydantic import BaseModel, Field
from datetime import datetime
from typing import Dict, Any

class EventMessage(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Event generation time")
    phase: str = Field(..., description="Current execution phase")
    severity: str = Field(..., description="INFO, WARNING, ERROR, CRITICAL")
    message: str = Field(..., description="Event description")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional contextual data")
