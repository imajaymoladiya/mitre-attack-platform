import logging
import sys
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database.mongo import mongo_client
from app.database.neo4j_db import neo4j_client
from app.routes import mitre

from contextlib import asynccontextmanager

# Setup structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up MITRE API Backend...")
    
    # Connect to MongoDB
    mongo_connected = False
    try:
        mongo_client.connect()
        mongo_connected = True
    except Exception as e:
        logger.error(f"Startup MongoDB connection failed: {e}")
        
    # Connect to Neo4j
    neo4j_connected = False
    try:
        neo4j_client.connect()
        neo4j_connected = True
    except Exception as e:
        logger.error(f"Startup Neo4j connection failed: {e}")

    # One-time database initialization
    if mongo_connected and neo4j_connected:
        try:
            entity_count = mongo_client.entities.count_documents({})
            if entity_count == 0:
                logger.info("MongoDB is empty. Initiating one-time database initialization...")
                import os
                import json
                from app.services.ingestion import ingest_stix_bundle
                
                # Path to sample dataset inside the package
                base_dir = os.path.dirname(os.path.abspath(__file__))
                sample_path = os.path.join(base_dir, "data", "enterprise-attack-sample.json")
                
                if os.path.exists(sample_path):
                    with open(sample_path, "r", encoding="utf-8") as f:
                        sample_data = json.load(f)
                    
                    logger.info(f"Ingesting sample dataset from {sample_path}")
                    result = ingest_stix_bundle(sample_data, "1.0-sample")
                    logger.info(f"One-time database initialization complete: {result}")
                else:
                    logger.warning(f"Sample dataset file not found at {sample_path}")
            else:
                logger.info(f"Database already initialized with {entity_count} entities.")
        except Exception as e:
            logger.error(f"One-time database initialization failed: {e}", exc_info=True)

    yield  # Hand over control to the application

    logger.info("Shutting down MITRE API Backend...")
    mongo_client.close()
    neo4j_client.close()

# Initialize FastAPI App
app = FastAPI(
    title="MITRE ATT&CK Data Management API",
    description="A secure modular AI platform for storing, traversing, and searching MITRE ATT&CK datasets.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Enable CORS for frontend and development use
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Healthcheck Endpoint
@app.get("/health", tags=["Health"])
async def health_check():
    """
    Service health check endpoint.
    Checks connectivity to MongoDB and Neo4j.
    """
    mongo_ok = False
    neo4j_ok = False
    
    try:
        if mongo_client.client:
            mongo_client.client.server_info()
            mongo_ok = True
    except Exception:
        pass
        
    try:
        if neo4j_client.driver:
            neo4j_client.driver.verify_connectivity()
            neo4j_ok = True
    except Exception:
        pass
        
    status_code = 200 if (mongo_ok and neo4j_ok) else 503
    return {
        "status": "healthy" if status_code == 200 else "degraded",
        "mongodb": "connected" if mongo_ok else "disconnected",
        "neo4j": "connected" if neo4j_ok else "disconnected"
    }

# Wire up routers
app.include_router(mitre.router)
