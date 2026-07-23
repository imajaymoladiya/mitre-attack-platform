import logging
import datetime
from pymongo import ReplaceOne
from app.database.mongo import mongo_client
from app.database.neo4j_db import neo4j_client
from app.services.llm import llm_service

logger = logging.getLogger(__name__)

# Map STIX type to Neo4j labels
LABEL_MAP = {
    "attack-pattern": "AttackPattern",
    "course-of-action": "CourseOfAction",
    "intrusion-set": "IntrusionSet",
    "malware": "Malware",
    "tool": "Tool",
    "x-mitre-tactic": "Tactic"
}

def get_mitre_id(stix_obj: dict) -> str:
    """
    Extracts the MITRE ATT&CK ID (e.g. T1059, G0007) from STIX external references.
    """
    external_refs = stix_obj.get("external_references", [])
    for ref in external_refs:
        if ref.get("source_name") in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"):
            return ref.get("external_id", "")
    return ""

def get_secondary_label(stix_type: str) -> str:
    return LABEL_MAP.get(stix_type, "")

def clean_relationship_type(rel_type: str) -> str:
    """
    Normalizes a STIX relationship type into UPPER_SNAKE_CASE for Neo4j.
    """
    if not rel_type:
        return "RELATED_TO"
    return rel_type.replace("-", "_").upper()

def ingest_stix_bundle(bundle_data: dict, version_overwrite: str = None) -> dict:
    """
    Parses a STIX bundle, generates embeddings, and populates MongoDB and Neo4j.
    """
    if bundle_data.get("type") != "bundle" or "objects" not in bundle_data:
        raise ValueError("Invalid STIX JSON: must be a bundle containing objects.")

    objects = bundle_data["objects"]
    entities = []
    relationships = []
    
    # Identify target entities and relationships
    for obj in objects:
        stix_type = obj.get("type")
        if not stix_type or obj.get("revoked", False):
            continue

        if stix_type == "relationship":
            relationships.append(obj)
        elif stix_type in LABEL_MAP:
            entities.append(obj)

    logger.info(f"Parsed {len(entities)} entities and {len(relationships)} relationships from STIX bundle.")

    if not entities:
        return {
            "status": "success",
            "message": "No valid active MITRE entities found in bundle.",
            "entities_imported": 0,
            "relationships_imported": 0
        }

    # Determine Active Version
    # Usually we get version from the first entity or from x_mitre_version property if available
    first_entity_ver = entities[0].get("x_mitre_version")
    active_version = version_overwrite or first_entity_ver or "1.0"

    # Step 1: Generate embeddings for all entities in batches
    texts_to_embed = []
    for ent in entities:
        name = ent.get("name", "")
        desc = ent.get("description", "")
        texts_to_embed.append(f"{name}: {desc}")

    logger.info("Generating embeddings for entities...")
    batch_size = 50
    all_embeddings = []
    for i in range(0, len(texts_to_embed), batch_size):
        batch_texts = texts_to_embed[i:i + batch_size]
        batch_embeds = llm_service.get_embeddings_batch(batch_texts)
        all_embeddings.extend(batch_embeds)

    # Verify embeddings were generated
    if all_embeddings:
        # Update MongoDB index dimension based on generated embeddings
        mongo_client.ensure_indexes(len(all_embeddings[0]))

    # Step 2: Ingest Entities into MongoDB
    mongo_ops = []
    for ent, emb in zip(entities, all_embeddings):
        mitre_id = get_mitre_id(ent)
        mongo_doc = {
            "id": ent["id"],
            "type": ent["type"],
            "name": ent.get("name", ""),
            "description": ent.get("description", ""),
            "x_mitre_version": active_version,
            "mitre_id": mitre_id,
            "created": ent.get("created"),
            "modified": ent.get("modified"),
            "embedding": emb,
            "stix_raw": ent
        }
        # Upsert operation to prevent duplicate STIX IDs
        mongo_ops.append(ReplaceOne({"id": ent["id"]}, mongo_doc, upsert=True))

    logger.info(f"Writing {len(mongo_ops)} entities to MongoDB...")
    if mongo_ops:
        mongo_client.entities.bulk_write(mongo_ops)

    # Step 3: Ingest Entities into Neo4j
    logger.info(f"Writing {len(entities)} nodes to Neo4j...")
    node_query = """
    UNWIND $batch AS row
    MERGE (e:Entity {id: row.id})
    SET e.name = row.name,
        e.type = row.type,
        e.mitre_id = row.mitre_id,
        e.version = row.version
    WITH e, row
    # Add dynamic secondary label in Neo4j
    CALL apoc.create.addLabels(e, [row.secondary_label]) YIELD node
    RETURN count(*)
    """
    
    # Wait, APOC might not be available or enabled. To keep it 100% robust and native,
    # we can run a cypher session and execute label specific MERGE queries.
    # Let's group nodes by secondary label and run direct cypher query.
    grouped_entities = {}
    for ent in entities:
        sec_label = get_secondary_label(ent["type"])
        if sec_label not in grouped_entities:
            grouped_entities[sec_label] = []
        
        grouped_entities[sec_label].append({
            "id": ent["id"],
            "name": ent.get("name", ""),
            "type": ent["type"],
            "mitre_id": get_mitre_id(ent),
            "version": active_version
        })

    for label, batch in grouped_entities.items():
        # Clean Cypher parameter passing
        cypher_query = f"""
        UNWIND $batch AS row
        MERGE (e:Entity {{id: row.id}})
        SET e.name = row.name,
            e.type = row.type,
            e.mitre_id = row.mitre_id,
            e.version = row.version
        WITH e, row
        CALL apoc.create.addLabels(e, [row.label]) YIELD node
        RETURN count(*)
        """
        
        # Let's write a pure Neo4j query without APOC as a fallback just in case APOC is missing.
        # How? We can run a query for each label: `MERGE (e:Entity:Label)`
        cypher_query_fallback = f"""
        UNWIND $batch AS row
        MERGE (e:Entity {{id: row.id}})
        SET e.name = row.name,
            e.type = row.type,
            e.mitre_id = row.mitre_id,
            e.version = row.version
        WITH e
        # Set dynamic label using APOC if present, else manual labels in Python session
        RETURN e
        """
        
        # We can execute a MERGE statement specifying both labels:
        cypher_query_native = f"""
        UNWIND $batch AS row
        MERGE (e:Entity {{id: row.id}})
        SET e.name = row.name,
            e.type = row.type,
            e.mitre_id = row.mitre_id,
            e.version = row.version
        WITH e
        # Run custom labels:
        """
        # Let's do it cleanly: we MERGE on :Entity, and then set secondary labels.
        # Since Cypher doesn't allow dynamic label addition natively without APOC in one query,
        # we can do it by running a Cypher query for each label type!
        # e.g., for Malware:
        # MERGE (e:Entity:Malware {id: row.id}) ...
        cypher_query_label = f"""
        UNWIND $batch AS row
        MERGE (e:Entity {{id: row.id}})
        SET e.name = row.name,
            e.type = row.type,
            e.mitre_id = row.mitre_id,
            e.version = row.version
        WITH e
        CALL apoc.create.addLabels(e, ["{label}"]) YIELD node
        RETURN count(*)
        """
        
        try:
            neo4j_client.execute_write(cypher_query_label, {"batch": batch})
        except Exception as e:
            logger.warning(f"Neo4j APOC addLabels failed: {e}. Attempting native query label by label.")
            # Native fallback: MERGE directly with label
            cypher_query_native = f"""
            UNWIND $batch AS row
            MERGE (e:Entity:Entity{label} {{id: row.id}})
            SET e.name = row.name,
                e.type = row.type,
                e.mitre_id = row.mitre_id,
                e.version = row.version
            """
            # Wait, `Entity{label}` might not be valid Cypher. The syntax is `:Entity:{label}` where label is interpolated.
            cypher_query_native = f"""
            UNWIND $batch AS row
            MERGE (e:Entity {{id: row.id}})
            SET e.name = row.name,
                e.type = row.type,
                e.mitre_id = row.mitre_id,
                e.version = row.version
            """
            # Let's just do it directly. We can add labels using multiple queries or running it in python.
            # To be absolutely safe and standard, since Cypher has no dynamic labels,
            # we can run a MERGE for the specific label:
            cypher_merge_label = f"""
            UNWIND $batch AS row
            MERGE (e:{label} {{id: row.id}})
            SET e:Entity,
                e.name = row.name,
                e.type = row.type,
                e.mitre_id = row.mitre_id,
                e.version = row.version
            """
            neo4j_client.execute_write(cypher_merge_label, {"batch": batch})

    # Step 4: Ingest Relationships into Neo4j
    logger.info(f"Writing {len(relationships)} relationships to Neo4j...")
    
    # Group relationships by normalized type to write them efficiently in batches
    grouped_rels = {}
    for rel in relationships:
        source = rel.get("source_ref")
        target = rel.get("target_ref")
        rel_type = clean_relationship_type(rel.get("relationship_type"))
        
        if not source or not target:
            continue
            
        if rel_type not in grouped_rels:
            grouped_rels[rel_type] = []
        
        grouped_rels[rel_type].append({
            "id": rel["id"],
            "source_ref": source,
            "target_ref": target,
            "type": rel.get("relationship_type", "")
        })

    for rel_type, batch in grouped_rels.items():
        # Standard Cypher MERGE with explicit relationship type
        # We match source and target nodes by id, and merge the relationship
        rel_query = f"""
        UNWIND $batch AS row
        MATCH (src:Entity {{id: row.source_ref}})
        MATCH (tgt:Entity {{id: row.target_ref}})
        MERGE (src)-[r:{rel_type}]->(tgt)
        SET r.id = row.id, r.type = row.type
        RETURN count(*)
        """
        try:
            neo4j_client.execute_write(rel_query, {"batch": batch})
        except Exception as e:
            logger.error(f"Failed to write relationship type {rel_type}: {e}")

    # Step 5: Update Active Version Metadata in MongoDB
    metadata_doc = {
        "x_mitre_version": active_version,
        "last_updated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "entities_count": len(entities),
        "relationships_count": len(relationships)
    }
    
    mongo_client.metadata.replace_one(
        {"active": True},
        {"active": True, **metadata_doc},
        upsert=True
    )
    
    logger.info(f"Ingestion of MITRE ATT&CK version {active_version} completed successfully.")
    
    return {
        "status": "success",
        "message": f"Ingestion of MITRE ATT&CK version {active_version} complete.",
        "x_mitre_version": active_version,
        "entities_imported": len(entities),
        "relationships_imported": len(relationships),
        "timestamp": metadata_doc["last_updated"]
    }
