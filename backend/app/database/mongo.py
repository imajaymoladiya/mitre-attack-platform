import logging
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from app.config import settings

logger = logging.getLogger(__name__)

class MongoDBClient:
    def __init__(self):
        self.client = None
        self.db = None
        self.entities = None
        self.metadata = None

    def connect(self):
        try:
            logger.info(f"Connecting to MongoDB at {settings.MONGO_URI}")
            self.client = MongoClient(settings.MONGO_URI, serverSelectionTimeoutMS=5000)
            # Trigger connection check
            self.client.server_info()
            
            self.db = self.client[settings.MONGO_DB_NAME]
            self.entities = self.db["mitre_entities"]
            self.metadata = self.db["mitre_metadata"]
            
            logger.info("Successfully connected to MongoDB.")
        except PyMongoError as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise e

    def close(self):
        if self.client:
            self.client.close()
            logger.info("MongoDB connection closed.")

    def ensure_indexes(self, embedding_dim: int):
        if self.entities is None:
            return
        
        try:
            # 1. Standard unique index on STIX ID
            self.entities.create_index("id", unique=True)
            # 2. Index on type and version for fast filtering
            self.entities.create_index([("x_mitre_version", 1), ("type", 1)])
            self.entities.create_index("mitre_id")
            logger.info("Standard MongoDB indexes verified.")
            
            # 3. Vector search index creation for MongoDB 8.0/Atlas search
            # We list existing search indexes to check if it already exists
            existing_indexes = list(self.entities.list_search_indexes())
            index_exists = any(idx.get("name") == "vector_index" for idx in existing_indexes)
            
            if not index_exists:
                logger.info(f"Creating vector search index 'vector_index' with dimension={embedding_dim}")
                index_model = {
                    "name": "vector_index",
                    "definition": {
                        "mappings": {
                            "dynamic": False,
                            "fields": {
                                "embedding": {
                                    "type": "knnVector",
                                    "dimensions": embedding_dim,
                                    "similarity": "cosine"
                                }
                            }
                        }
                    }
                }
                self.entities.create_search_index(model=index_model)
                logger.info("Vector search index creation requested (asynchronous on server).")
            else:
                logger.info("Vector search index already exists.")
        except Exception as e:
            logger.warning(
                f"Failed to verify/create search index: {e}. "
                "Vector Search will still fall back to standard querying if not fully initialized or if mongot is not running."
            )

# Global database instance
mongo_client = MongoDBClient()
