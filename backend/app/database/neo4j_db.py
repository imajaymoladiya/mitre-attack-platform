import logging
from neo4j import GraphDatabase, exceptions
from app.config import settings

logger = logging.getLogger(__name__)

class Neo4jClient:
    def __init__(self):
        self.driver = None

    def connect(self):
        try:
            logger.info(f"Connecting to Neo4j at {settings.NEO4J_URI}")
            self.driver = GraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD)
            )
            # Verify connectivity
            self.driver.verify_connectivity()
            logger.info("Successfully connected to Neo4j.")
            
            # Ensure database constraints
            self.ensure_constraints()
        except exceptions.Neo4jError as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            raise e

    def close(self):
        if self.driver:
            self.driver.close()
            logger.info("Neo4j connection closed.")

    def ensure_constraints(self):
        """
        Creates unique constraints on the entity 'id' property in Neo4j 5.
        """
        if not self.driver:
            return
        
        query = "CREATE CONSTRAINT entity_id_unique IF NOT EXISTS FOR (e:Entity) REQUIRE e.id IS UNIQUE"
        
        try:
            with self.driver.session() as session:
                session.run(query)
                # Create standard indexes on type and name for fast lookups
                session.run("CREATE INDEX entity_type_idx IF NOT EXISTS FOR (n:Entity) ON (n.type)")
                session.run("CREATE INDEX entity_mitre_id_idx IF NOT EXISTS FOR (n:Entity) ON (n.mitre_id)")
                logger.info("Neo4j constraints and indexes verified.")
        except Exception as e:
            logger.warning(f"Could not create Neo4j constraints: {e}")

    def execute_read(self, query: str, parameters: dict = None):
        if not self.driver:
            raise RuntimeError("Neo4j driver is not connected.")
        with self.driver.session() as session:
            result = session.run(query, parameters or {})
            return [record.data() for record in result]

    def execute_write(self, query: str, parameters: dict = None):
        if not self.driver:
            raise RuntimeError("Neo4j driver is not connected.")
        with self.driver.session() as session:
            result = session.run(query, parameters or {})
            return [record.data() for record in result]

# Global database instance
neo4j_client = Neo4jClient()
