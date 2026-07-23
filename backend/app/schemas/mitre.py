from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List

class SemanticSearchRequest(BaseModel):
    query: str = Field(..., description="The natural language text query to search.")
    limit: Optional[int] = Field(10, ge=1, le=100, description="Max results to return.")
    entity_type: Optional[str] = Field(None, description="Filter by STIX entity type (e.g. malware, tool).")

class CypherQueryRequest(BaseModel):
    query: str = Field(..., description="Neo4j Cypher query to execute.")
    parameters: Optional[Dict[str, Any]] = Field(None, description="Query parameters.")

class LineageRequest(BaseModel):
    mitre_id: str = Field(..., description="The MITRE ID to traverse (e.g. T1059).")
    depth: Optional[int] = Field(2, ge=1, le=5, description="Depth of traversal (max 5).")

class VersionMetadataResponse(BaseModel):
    x_mitre_version: str
    last_updated: str
    entities_count: int
    relationships_count: int

class SearchResultResponse(BaseModel):
    id: str
    type: str
    name: str
    description: str
    x_mitre_version: str
    mitre_id: str
    score: float
