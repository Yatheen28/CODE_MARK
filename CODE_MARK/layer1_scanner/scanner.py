import os
import re
import docx
from pdfminer.high_level import extract_text
from presidio_analyzer import AnalyzerEngine

analyzer = AnalyzerEngine()

EMAIL_RE = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
CPR_RE = re.compile(r'\b\d{6}-\d{4}\b')

def scan_text(text, source):
    """
    Scan text for PII using Presidio, email regex, and CPR regex
    
    Args:
        text: Text content to scan
        source: Source identifier (filename, table name, etc.)
    
    Returns:
        List of fragment dictionaries
    """
    results = []
    
    try:
        # Presidio analysis
        presidio_results = analyzer.analyze(text=text, language='en')
        for r in presidio_results:
            results.append({
                "type": r.entity_type,
                "value": text[r.start:r.end],
                "source": source
            })
    except Exception as e:
        print(f"Presidio analysis error: {e}")

    # Email regex
    for m in EMAIL_RE.finditer(text):
        results.append({"type": "EMAIL_ADDRESS", "value": m.group(), "source": source})
    
    # CPR (Nordic ID) regex
    for m in CPR_RE.finditer(text):
        results.append({"type": "CPR", "value": m.group(), "source": source})
    
    return results


def scan_job(file_objs=None, folder_paths=None, sample_n=200):
    """
    Main scanning function for files and folders
    
    Args:
        file_objs: List of tuples (filename, bytes)
        folder_paths: List of folder paths to scan
        sample_n: Sample size (not used for files but kept for compatibility)
    
    Returns:
        List of fragment dictionaries
    """
    fragments = []
    
    # Scan uploaded files
    if file_objs:
        for name, b in file_objs:
            try:
                text = b.decode('utf-8', errors='ignore')
                fragments.extend(scan_text(text, source=name))
            except Exception as e:
                print(f"Error scanning {name}: {e}")
    
    # Scan folder paths
    if folder_paths:
        for path in folder_paths:
            if not os.path.exists(path):
                print(f"Path does not exist: {path}")
                continue
            
            try:
                for f in os.listdir(path):
                    full_path = os.path.join(path, f)
                    
                    # Skip directories
                    if os.path.isdir(full_path):
                        continue
                    
                    try:
                        if f.endswith(".txt") or f.endswith(".log"):
                            with open(full_path, 'r', encoding='utf-8', errors='ignore') as file:
                                text = file.read()
                        elif f.endswith(".docx"):
                            doc = docx.Document(full_path)
                            text = "\n".join([p.text for p in doc.paragraphs])
                        elif f.endswith(".pdf"):
                            text = extract_text(full_path)
                        else:
                            # Try reading as text for other files
                            with open(full_path, 'r', encoding='utf-8', errors='ignore') as file:
                                text = file.read()
                        
                        fragments.extend(scan_text(text, source=f))
                    except Exception as e:
                        print(f"Error processing {f}: {e}")
            except Exception as e:
                print(f"Error scanning folder {path}: {e}")
    
    return fragments


def scan_database(connection_string, tables=None, sample_n=200):
    """
    Scan SQL database for PII fragments (read-only, sampled)
    
    Args:
        connection_string: Database connection string
        tables: List of table names to scan (None = all tables)
        sample_n: Number of rows to sample per table
    
    Returns:
        List of fragment dictionaries
    """
    fragments = []
    
    if not connection_string:
        return fragments
    
    try:
        import sqlalchemy
        from sqlalchemy import create_engine, inspect, text
        
        # Create read-only engine
        engine = create_engine(
            connection_string, 
            execution_options={"isolation_level": "READ UNCOMMITTED"}
        )
        inspector = inspect(engine)
        
        # Get tables to scan
        if tables is None or not tables:
            tables = inspector.get_table_names()
        
        with engine.connect() as conn:
            for table in tables:
                try:
                    # Sample rows from table
                    query = text(f"SELECT * FROM {table} LIMIT :limit")
                    result = conn.execute(query, {"limit": sample_n})
                    
                    for row in result:
                        # Convert row to dict
                        row_dict = dict(row._mapping)
                        
                        # Scan each column value
                        for col, value in row_dict.items():
                            if value is not None:
                                text_value = str(value)
                                frags = scan_text(text_value, source=f"{table}.{col}")
                                fragments.extend(frags)
                
                except Exception as e:
                    print(f"Error scanning table {table}: {e}")
                    continue
        
        engine.dispose()
        return fragments
    
    except ImportError:
        print("SQLAlchemy not installed. Install with: pip install sqlalchemy")
        return []
    except Exception as e:
        print(f"Database scan error: {e}")
        return []


def scan_mongo(mongo_uri, database_name, collections=None, sample_n=200):
    """
    Scan MongoDB for PII fragments (read-only, sampled)
    
    Args:
        mongo_uri: MongoDB connection URI
        database_name: Database name to scan
        collections: List of collection names (None = all collections)
        sample_n: Number of documents to sample per collection
    
    Returns:
        List of fragment dictionaries
    """
    fragments = []
    
    if not mongo_uri or not database_name:
        return fragments
    
    try:
        from pymongo import MongoClient
        
        client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
        db = client[database_name]
        
        # Get collections to scan
        if collections is None or not collections:
            collections = db.list_collection_names()
        
        for coll_name in collections:
            try:
                collection = db[coll_name]
                
                # Sample documents
                documents = list(collection.find().limit(sample_n))
                
                for doc in documents:
                    # Flatten document and scan
                    for key, value in doc.items():
                        if value is not None and key != '_id':
                            text_value = str(value)
                            frags = scan_text(text_value, source=f"{coll_name}.{key}")
                            fragments.extend(frags)
            
            except Exception as e:
                print(f"Error scanning collection {coll_name}: {e}")
                continue
        
        client.close()
        return fragments
    
    except ImportError:
        print("PyMongo not installed. Install with: pip install pymongo")
        return []
    except Exception as e:
        print(f"MongoDB scan error: {e}")
        return []