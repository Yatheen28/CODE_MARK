"""
Final Fixed Entity Mapper
✓ Correct fragment counting (no duplication)
✓ Stats always accurate
✓ Clean, reliable for re-scans
✓ FIXED: Single get_statistics() function with erasures
"""
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path

DB_PATH = Path("layer1_mapper.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS entities (
            entity_id TEXT PRIMARY KEY,
            fragment_count INTEGER DEFAULT 0,
            confidence REAL DEFAULT 0.0,
            created_at TEXT,
            updated_at TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS fragments (
            frag_id TEXT PRIMARY KEY,
            entity_id TEXT,
            frag_type TEXT,
            value TEXT,
            source TEXT,
            confidence REAL,
            created_at TEXT,
            FOREIGN KEY (entity_id) REFERENCES entities(entity_id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS erasures (
            erasure_id TEXT PRIMARY KEY,
            entity_id TEXT,
            fragments_deleted INTEGER,
            requested_by TEXT,
            reason TEXT,
            timestamp TEXT
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_frag_entity ON fragments(entity_id)")
    conn.commit()
    conn.close()


def save_mapping(mapping, fragments):
    """
    Saves mapping results into SQLite with deduplication.
    Prevents fragment count inflation across rescans.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = datetime.utcnow().isoformat()

    # Step 1 — Clear old duplicates for the same entities
    entity_ids = list({v["entity_id"] for v in mapping.values()})
    for eid in entity_ids:
        cursor.execute("DELETE FROM fragments WHERE entity_id=?", (eid,))
        cursor.execute("DELETE FROM entities WHERE entity_id=?", (eid,))

    # Step 2 — Insert new entities and fragments cleanly
    grouped = {}
    for idx, info in mapping.items():
        eid = info["entity_id"]
        conf = info.get("confidence", 1.0)
        frag = fragments[idx]
        grouped.setdefault(eid, []).append({
            "type": frag.get("type", "UNKNOWN"),
            "value": frag.get("value", ""),
            "source": frag.get("source", "unknown"),
            "confidence": conf
        })

    for eid, frag_list in grouped.items():
        avg_conf = sum(f["confidence"] for f in frag_list) / len(frag_list)
        cursor.execute("""
            INSERT INTO entities (entity_id, fragment_count, confidence, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
        """, (eid, len(frag_list), avg_conf, timestamp, timestamp))

        for i, frag in enumerate(frag_list):
            frag_id = f"{eid}-{uuid.uuid4()}"
            cursor.execute("""
                INSERT INTO fragments (frag_id, entity_id, frag_type, value, source, confidence, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                frag_id, eid, frag["type"], frag["value"],
                frag["source"], frag["confidence"], timestamp
            ))

    conn.commit()
    conn.close()


def get_entity(entity_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM entities WHERE entity_id=?", (entity_id,))
    entity = cursor.fetchone()
    if not entity:
        conn.close()
        return None

    cursor.execute("SELECT * FROM fragments WHERE entity_id=?", (entity_id,))
    fragments = [dict(row) for row in cursor.fetchall()]
    entity_dict = dict(entity)
    entity_dict["fragment_count"] = len(fragments)

    conn.close()
    return {"entity": entity_dict, "fragments": fragments}


def list_entities(limit=20):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT entity_id, fragment_count, confidence, created_at, updated_at
        FROM entities ORDER BY updated_at DESC LIMIT ?
    """, (limit,))
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return results


def search_entities(query):
    """Search entities by name or email in fragments"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    search_pattern = f"%{query}%"
    cursor.execute("""
        SELECT DISTINCT e.entity_id, e.fragment_count, e.confidence, e.created_at
        FROM entities e
        JOIN fragments f ON e.entity_id = f.entity_id
        WHERE f.value LIKE ? OR f.frag_type LIKE ?
        ORDER BY e.updated_at DESC
        LIMIT 50
    """, (search_pattern, search_pattern))
    
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return results


def delete_fragment(frag_id, requested_by="system", reason="Manual deletion"):
    """
    Delete a single fragment and update entity fragment count.
    Returns (success, entity_id or error_message)
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Get the fragment to find its entity_id
        cursor.execute("SELECT entity_id FROM fragments WHERE frag_id=?", (frag_id,))
        result = cursor.fetchone()
        
        if not result:
            conn.close()
            return False, "Fragment not found"
        
        entity_id = result[0]
        
        # Delete the fragment
        cursor.execute("DELETE FROM fragments WHERE frag_id=?", (frag_id,))
        
        # Recount fragments for this entity
        cursor.execute("SELECT COUNT(*) FROM fragments WHERE entity_id=?", (entity_id,))
        new_count = cursor.fetchone()[0]
        
        if new_count == 0:
            # No fragments left, delete the entity
            cursor.execute("DELETE FROM entities WHERE entity_id=?", (entity_id,))
            
            # Log as erasure
            erasure_id = f"E-{uuid.uuid4()}"
            timestamp = datetime.utcnow().isoformat()
            cursor.execute("""
                INSERT INTO erasures (erasure_id, entity_id, fragments_deleted, requested_by, reason, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (erasure_id, entity_id, 1, requested_by, reason, timestamp))
        else:
            # Update fragment count
            cursor.execute("""
                UPDATE entities 
                SET fragment_count=?, updated_at=?
                WHERE entity_id=?
            """, (new_count, datetime.utcnow().isoformat(), entity_id))
        
        conn.commit()
        conn.close()
        return True, entity_id
        
    except Exception as e:
        conn.rollback()
        conn.close()
        return False, str(e)


def erase_entity(entity_id, requested_by="system", reason="GDPR Article 17"):
    """
    Completely erase an entity and all its fragments.
    Logs the erasure for compliance.
    Returns (success, fragment_count) tuple
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Check if entity exists first
        cursor.execute("SELECT COUNT(*) FROM entities WHERE entity_id=?", (entity_id,))
        entity_exists = cursor.fetchone()[0]
        
        if entity_exists == 0:
            conn.close()
            return False, 0
        
        # Count fragments before deletion
        cursor.execute("SELECT COUNT(*) FROM fragments WHERE entity_id=?", (entity_id,))
        frag_count = cursor.fetchone()[0]
        
        # Delete all fragments
        cursor.execute("DELETE FROM fragments WHERE entity_id=?", (entity_id,))
        
        # Delete entity
        cursor.execute("DELETE FROM entities WHERE entity_id=?", (entity_id,))
        
        # Log erasure
        erasure_id = f"ER-{uuid.uuid4()}"
        timestamp = datetime.utcnow().isoformat()
        cursor.execute("""
            INSERT INTO erasures (erasure_id, entity_id, fragments_deleted, requested_by, reason, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (erasure_id, entity_id, frag_count, requested_by, reason, timestamp))
        
        conn.commit()
        conn.close()
        return True, frag_count
        
    except Exception as e:
        conn.rollback()
        conn.close()
        print(f"Erasure failed: {e}")
        return False, 0


def get_statistics():
    """Get database statistics including erasures count - ALWAYS FRESH"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM entities")
    total_entities = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM fragments")
    total_fragments = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM erasures")
    erasures_performed = cursor.fetchone()[0]

    avg_fragments = round(total_fragments / total_entities, 2) if total_entities > 0 else 0.0
    
    conn.close()
    return {
        "total_entities": total_entities,
        "total_fragments": total_fragments,
        "avg_fragments_per_entity": avg_fragments,
        "erasures_performed": erasures_performed
    }