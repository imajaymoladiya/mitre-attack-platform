import json
import logging
from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks, status
from fastapi.responses import StreamingResponse
from app.database.mongo import mongo_client
from app.database.neo4j_db import neo4j_client
from app.schemas.mitre import (
    SemanticSearchRequest,
    CypherQueryRequest,
    LineageRequest,
    VersionMetadataResponse,
    SearchResultResponse
)
from app.services.ingestion import ingest_stix_bundle
from app.services.search import semantic_search, get_graph_lineage

router = APIRouter(prefix="/api/v1/mitre", tags=["MITRE ATT&CK"])
logger = logging.getLogger(__name__)

# Simple in-memory tracker for background ingestion status
INGESTION_STATUS = {
    "status": "idle",
    "message": "No active ingestion.",
    "x_mitre_version": None,
    "entities_imported": 0,
    "relationships_imported": 0,
    "error": None
}

def run_ingestion_background(bundle_data: dict, version: str):
    global INGESTION_STATUS
    INGESTION_STATUS["status"] = "processing"
    INGESTION_STATUS["message"] = f"Ingesting version {version}..."
    INGESTION_STATUS["x_mitre_version"] = version
    INGESTION_STATUS["error"] = None
    
    try:
        result = ingest_stix_bundle(bundle_data, version)
        INGESTION_STATUS["status"] = "completed"
        INGESTION_STATUS["message"] = "Ingestion completed successfully."
        INGESTION_STATUS["entities_imported"] = result.get("entities_imported", 0)
        INGESTION_STATUS["relationships_imported"] = result.get("relationships_imported", 0)
    except Exception as e:
        logger.error(f"Background ingestion failed: {e}")
        INGESTION_STATUS["status"] = "failed"
        INGESTION_STATUS["message"] = "Ingestion failed."
        INGESTION_STATUS["error"] = str(e)

@router.get("/version", response_model=VersionMetadataResponse)
async def get_version():
    """
    Returns the active version metadata of the MITRE dataset.
    """
    if mongo_client.metadata is None:
        raise HTTPException(status_code=500, detail="Database not connected.")
    
    meta = mongo_client.metadata.find_one({"active": True})
    if not meta:
        raise HTTPException(
            status_code=404, 
            detail="No active MITRE dataset version found. Please upload a dataset."
        )
    
    return {
        "x_mitre_version": meta["x_mitre_version"],
        "last_updated": meta["last_updated"],
        "entities_count": meta.get("entities_count", 0),
        "relationships_count": meta.get("relationships_count", 0)
    }

@router.get("/ingestion-status")
async def get_ingestion_status():
    """
    Returns the current status of background ingestion.
    """
    return INGESTION_STATUS

@router.get("")
async def download_dataset():
    """
    Streams the active MITRE dataset as a STIX bundle JSON file.
    """
    if mongo_client.metadata is None:
        raise HTTPException(status_code=500, detail="Database not connected.")
    
    meta = mongo_client.metadata.find_one({"active": True})
    if not meta:
        raise HTTPException(status_code=404, detail="No active dataset available.")
    
    version = meta["x_mitre_version"]

    def stix_bundle_generator():
        yield '{"type": "bundle", "id": "bundle--custom", "objects": ['
        cursor = mongo_client.entities.find({"x_mitre_version": version}, {"stix_raw": 1, "_id": 0})
        first = True
        for doc in cursor:
            stix_obj = doc.get("stix_raw")
            if stix_obj:
                chunk = ""
                if not first:
                    chunk += ","
                chunk += json.dumps(stix_obj)
                first = False
                yield chunk
        yield "]}"

    headers = {
        "Content-Disposition": f'attachment; filename="mitre-attack-{version}.json"',
        "Content-Type": "application/json"
    }
    return StreamingResponse(stix_bundle_generator(), headers=headers)

@router.put("/{x_mitre_version}", status_code=status.HTTP_202_ACCEPTED)
async def upload_dataset(
    x_mitre_version: str,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    """
    Uploads a STIX JSON file and triggers background ingestion.
    """
    global INGESTION_STATUS
    if INGESTION_STATUS["status"] == "processing":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An ingestion task is already running in the background."
        )

    # Read and parse file
    try:
        content = await file.read()
        bundle_data = json.loads(content)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Uploaded file is not valid JSON.")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read file: {e}")

    # Validate basic STIX bundle structure
    if bundle_data.get("type") != "bundle" or "objects" not in bundle_data:
        raise HTTPException(status_code=400, detail="JSON must be a STIX bundle containing an 'objects' list.")

    # Schedule background ingestion
    background_tasks.add_task(run_ingestion_background, bundle_data, x_mitre_version)
    
    # Set initial status
    INGESTION_STATUS["status"] = "processing"
    INGESTION_STATUS["message"] = f"Ingestion started for version {x_mitre_version}."
    INGESTION_STATUS["x_mitre_version"] = x_mitre_version

    return {
        "status": "accepted",
        "message": f"Dataset version {x_mitre_version} accepted. Ingestion running in background."
    }

@router.post("/search", response_model=list[SearchResultResponse])
async def search_mitre(request: SemanticSearchRequest):
    """
    Performs semantic vector search on MITRE entities.
    """
    try:
        results = semantic_search(
            query_text=request.query,
            limit=request.limit,
            entity_type=request.entity_type
        )
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/query")
async def run_cypher(request: CypherQueryRequest):
    """
    Executes a custom Neo4j Cypher query and returns the records.
    """
    try:
        records = neo4j_client.execute_write(request.query, request.parameters)
        return {"records": records}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Cypher execution failed: {e}")

@router.post("/lineage")
async def get_lineage(request: LineageRequest):
    """
    Retrieves the relationship lineage graph for a specific MITRE ID (e.g. T1059).
    """
    try:
        graph_data = get_graph_lineage(
            start_mitre_id=request.mitre_id,
            depth=request.depth
        )
        return graph_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
