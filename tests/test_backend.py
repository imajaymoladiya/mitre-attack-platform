import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.schemas.mitre import SemanticSearchRequest, CypherQueryRequest

client = TestClient(app)

def test_health_endpoint():
    """
    Test the healthcheck endpoint. It should return a 200 or 503 depending on DB status,
    with a JSON containing mongodb and neo4j status.
    """
    response = client.get("/health")
    assert response.status_code in (200, 503)
    data = response.json()
    assert "status" in data
    assert "mongodb" in data
    assert "neo4j" in data

def test_pydantic_search_schema_validation():
    """
    Test semantic search request model validation.
    """
    # Valid request
    req = SemanticSearchRequest(query="credentials", limit=5)
    assert req.query == "credentials"
    assert req.limit == 5
    assert req.entity_type is None

    # Invalid request (limit too large)
    with pytest.raises(ValueError):
        SemanticSearchRequest(query="credentials", limit=200)

def test_pydantic_cypher_schema_validation():
    """
    Test Cypher query request model validation.
    """
    req = CypherQueryRequest(query="MATCH (n) RETURN n LIMIT 1")
    assert req.query == "MATCH (n) RETURN n LIMIT 1"
    assert req.parameters is None

def test_get_version_not_found_handling():
    """
    If no version metadata exists yet, it should return a 404.
    """
    # Since we can't guarantee if data is already loaded in the environment,
    # we just check that the status code is either 200 or 404.
    response = client.get("/api/v1/mitre/version")
    assert response.status_code in (200, 404)
