import os
from dotenv import load_dotenv

# Load local environment if available (useful for non-docker local testing)
load_dotenv()

class Settings:
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    
    # MongoDB
    MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://admin:adminpassword@mongodb:27017/?authSource=admin")
    MONGO_DB_NAME: str = os.getenv("MONGO_DB_NAME", "mitre_db")
    
    # Neo4j
    NEO4J_URI: str = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
    NEO4J_USER: str = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "neo4jpassword")
    
    # LLM / Embeddings
    LLM_API_BASE: str = os.getenv("LLM_API_BASE", "http://host.docker.internal:1234/v1")
    LLM_MODEL_NAME: str = os.getenv("LLM_MODEL_NAME", "nomic-ai/nomic-embed-text-v1.5-GGUF")
    USE_LOCAL_EMBEDDING_FALLBACK: bool = os.getenv("USE_LOCAL_EMBEDDING_FALLBACK", "true").lower() == "true"
    
    # Groq Integration
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL_NAME: str = os.getenv("GROQ_MODEL_NAME", "llama3-8b-8192")

settings = Settings()
