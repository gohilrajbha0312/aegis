from pydantic import BaseModel, Field
from datetime import datetime
from typing import List

class KnowledgeItem(BaseModel):
    id: str = Field(..., description="Unique knowledge item ID")
    category: str = Field(..., description="e.g., attack_patterns, recon_rules")
    title: str = Field(..., description="Title of the knowledge item")
    content: str = Field(..., description="Detailed content or rule definition")
    tags: List[str] = Field(default_factory=list, description="Tags for semantic retrieval")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in this knowledge")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
