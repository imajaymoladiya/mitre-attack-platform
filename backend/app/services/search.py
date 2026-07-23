import logging
from app.database.mongo import mongo_client
from app.database.neo4j_db import neo4j_client
from app.services.llm import llm_service

logger = logging.getLogger(__name__)

def semantic_search(query_text: str, limit: int = 10, entity_type: str = None) -> list[dict]:
    """
    Performs semantic vector search on MongoDB.
    Falls back to regex-based keyword search if vector index is not built/active.
    """
    if mongo_client.entities is None:
        raise RuntimeError("MongoDB is not connected.")

    # 1. Generate query embedding
    try:
        query_vector = llm_service.get_embedding(query_text)
    except Exception as e:
        logger.error(f"Failed to generate embedding for query: {e}")
        query_vector = None

    # 2. Try Vector Search
    if query_vector:
        vector_search_stage = {
            "$vectorSearch": {
                "index": "vector_index",
                "path": "embedding",
                "queryVector": query_vector,
                "numCandidates": max(100, limit * 2),
                "limit": limit
            }
        }
        
        # Add pre-filtering by entity type if specified
        if entity_type:
            vector_search_stage["$vectorSearch"]["filter"] = {"type": entity_type}
            
        pipeline = [
            vector_search_stage,
            {
                "$project": {
                    "_id": 0,
                    "id": 1,
                    "type": 1,
                    "name": 1,
                    "description": 1,
                    "x_mitre_version": 1,
                    "mitre_id": 1,
                    "score": {"$meta": "vectorSearchScore"}
                }
            }
        ]
        
        try:
            results = list(mongo_client.entities.aggregate(pipeline))
            logger.info(f"Vector search returned {len(results)} results.")
            return results
        except Exception as e:
            logger.warning(
                f"Vector search execution failed ({e}). "
                "Vector index may still be building. Falling back to regex keyword search."
            )

    # 3. Fallback: Regex Keyword Search
    # Search name and description for query keywords
    fallback_query = {
        "$or": [
            {"name": {"$regex": query_text, "$options": "i"}},
            {"description": {"$regex": query_text, "$options": "i"}}
        ]
    }
    if entity_type:
        fallback_query["type"] = entity_type

    try:
        results = list(mongo_client.entities.find(fallback_query, {"_id": 0, "embedding": 0}).limit(limit))
        # Assign artificial score for consistency in the response contract
        for doc in results:
            doc["score"] = 0.5  # Neutral fallback score
        logger.info(f"Regex search fallback returned {len(results)} results.")
        return results
    except Exception as e:
        logger.error(f"Fallback search failed: {e}")
        return []

def get_graph_lineage(start_mitre_id: str, depth: int = 2) -> dict:
    """
    Traverses Neo4j relationships starting from a specific MITRE ID up to a certain depth.
    Returns nodes and edges in a structure optimized for UI visualization.
    """
    if not neo4j_client.driver:
        raise RuntimeError("Neo4j is not connected.")

    # Match relationships up to the specified depth
    query = f"""
    MATCH (start:Entity {{mitre_id: $mitre_id}})
    MATCH path = (start)-[r*1..{depth}]-(end:Entity)
    RETURN path LIMIT 100
    """
    
    try:
        records = neo4j_client.execute_read(query, {"mitre_id": start_mitre_id})
        
        nodes_dict = {}
        edges_list = []
        seen_edges = set()

        for record in records:
            path = record["path"]
            # Extract nodes from the path
            for node in path.nodes:
                node_id = node["id"]
                if node_id not in nodes_dict:
                    nodes_dict[node_id] = {
                        "id": node_id,
                        "name": node.get("name", ""),
                        "type": node.get("type", ""),
                        "mitre_id": node.get("mitre_id", ""),
                        "version": node.get("version", "")
                    }
            
            # Extract relationships from the path
            for rel in path.relationships:
                # rel.nodes contains start and end nodes of this specific segment
                start_id = rel.nodes[0]["id"]
                end_id = rel.nodes[1]["id"]
                edge_id = rel.get("id") or f"{start_id}-{rel.type}-{end_id}"
                
                if edge_id not in seen_edges:
                    seen_edges.add(edge_id)
                    edges_list.append({
                        "id": edge_id,
                        "source": start_id,
                        "target": end_id,
                        "type": rel.type
                    })

        # If no paths are traversed, return the start node itself (if it exists)
        if not nodes_dict:
            single_node_query = "MATCH (start:Entity {mitre_id: $mitre_id}) RETURN start"
            single_node = neo4j_client.execute_read(single_node_query, {"mitre_id": start_mitre_id})
            if single_node:
                node = single_node[0]["start"]
                nodes_dict[node["id"]] = {
                    "id": node["id"],
                    "name": node.get("name", ""),
                    "type": node.get("type", ""),
                    "mitre_id": node.get("mitre_id", ""),
                    "version": node.get("version", "")
                }

        return {
            "nodes": list(nodes_dict.values()),
            "edges": edges_list
        }
    except Exception as e:
        logger.error(f"Graph traversal query failed: {e}")
        raise e
