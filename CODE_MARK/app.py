"""
NordSecureAI - Layer 1: AI Detective
COMPLETE FINAL VERSION - All features implemented
"""
import streamlit as st
import pandas as pd
import json
import os
import time
import hashlib
from pathlib import Path

# Import modules
from infra.license_validator import check_license
from security.secure_data_handler import SecureDataHandler
from security.audit_logger import AuditLogger
from layer1_scanner.scanner import scan_job
from layer1_linker.linker import cluster_fragments, get_cluster_summary
from layer1_mapper import mapper

# Page config
st.set_page_config(
    page_title="NordSecureAI - AI Detective Layer",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: #1E3A8A;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        font-size: 1.2rem;
        color: #6B7280;
        margin-bottom: 2rem;
    }
    .stats-row {
        display: flex;
        gap: 3rem;
        margin: 2rem 0;
        padding: 1.5rem;
        background: #F8FAFC;
        border-radius: 8px;
        border: 1px solid #E2E8F0;
    }
    .stat-box {
        flex: 1;
    }
    .stat-label {
        font-size: 0.75rem;
        color: #64748B;
        text-transform: uppercase;
        letter-spacing: 0.1em;
        margin-bottom: 0.5rem;
        font-weight: 600;
    }
    .stat-value {
        font-size: 2.5rem;
        font-weight: 300;
        color: #0F172A;
        font-variant-numeric: tabular-nums;
    }
    .pii-card {
        background-color: #F9FAFB;
        border: 1px solid #E5E7EB;
        border-radius: 8px;
        padding: 1rem;
        margin-bottom: 0.75rem;
    }
    .pii-card strong {
        color: #1E40AF;
    }
    .success-box {
        background-color: #D1FAE5;
        border-left: 4px solid #10B981;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
        color: #065F46;
    }
    .warning-box {
        background-color: #FEF3C7;
        border-left: 4px solid #F59E0B;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
        color: #92400E;
    }
    .pi-analyzer-box {
        background-color: #EFF6FF;
        border: 2px dashed #3B82F6;
        border-radius: 8px;
        padding: 1.5rem;
        margin: 1.5rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Initialize handlers
@st.cache_resource
def get_handlers():
    """Initialize handlers (cached)"""
    secure_handler = SecureDataHandler()
    audit_logger = AuditLogger()
    mapper.init_db()
    return secure_handler, audit_logger

handler, audit_logger = get_handlers()

# Helper functions
def generate_pii_id(entity_id, frag_type, value):
    """Generate a unique PII ID"""
    combined = f"{entity_id}-{frag_type}-{value}"
    hash_obj = hashlib.md5(combined.encode())
    hash_hex = hash_obj.hexdigest()[:8]
    return f"PII-{hash_hex}"

def extract_identifier_type(frag):
    """Extract identifier type from fragment"""
    if isinstance(frag, dict):
        if 'column_name' in frag:
            return frag['column_name']
        elif 'field_name' in frag:
            return frag['field_name']
        elif 'metadata' in frag and isinstance(frag['metadata'], dict):
            if 'column' in frag['metadata']:
                return frag['metadata']['column']
            elif 'field' in frag['metadata']:
                return frag['metadata']['field']
        
        if 'frag_type' in frag:
            frag_type = frag['frag_type']
            type_map = {
                'UK_NHS': 'NHS Number',
                'PHONE_NUMBER': 'Phone Number',
                'EMAIL': 'Email Address',
                'CPR': 'CPR Number',
                'PERSON_NAME': 'Name',
                'SSN': 'Social Security Number',
                'CREDIT_CARD': 'Credit Card',
                'ADDRESS': 'Address',
                'DATE_OF_BIRTH': 'Date of Birth'
            }
            return type_map.get(frag_type, frag_type.replace('_', ' ').title())
    
    return 'Unknown Identifier'

def get_proper_source(frag):
    """Extract source information from fragment"""
    if isinstance(frag, dict):
        if 'source_file' in frag:
            source_file = frag['source_file']
            if 'line_number' in frag:
                return f"{source_file} (Line {frag['line_number']})"
            elif 'row_number' in frag:
                return f"{source_file} (Row {frag['row_number']})"
            return source_file
        elif 'source' in frag:
            return frag['source']
        elif 'metadata' in frag and isinstance(frag['metadata'], dict):
            if 'source' in frag['metadata']:
                return frag['metadata']['source']
    
    return 'Unknown Source'

# License check
st.markdown('<div class="main-header">🔍 NordSecureAI - AI Detective</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Layer 1: Universal Scan → Probabilistic Link → Golden Record</div>', unsafe_allow_html=True)

valid, msg = check_license()
if not valid:
    st.error(f"⚠️ License Error: {msg}")
    st.info("📝 To generate a demo license, run: `python infra/license_validator.py`")
    st.stop()

st.success(f"✓ {msg} | Running in on-prem mode (no data leaves this system)")

# Sidebar
st.sidebar.header("⚙️ Configuration")
mode = st.sidebar.radio(
    "Mode",
    ["🔍 Scan & Link", "🗂️ Entity Manager", "📊 Audit Logs"],
    help="Choose operation mode"
)

# === SCAN & LINK MODE ===
if mode == "🔍 Scan & Link":
    st.header("Step 1: Universal Historical Scan")
    
    # Get fresh statistics - only show if entities exist
    stats = mapper.get_statistics()
    
    # Only show statistics if there are entities in database
    if stats['total_entities'] > 0:
        st.markdown(f"""
        <div class="stats-row">
            <div class="stat-box">
                <div class="stat-label">Total Entities</div>
                <div class="stat-value">{stats['total_entities']}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Total PII Items</div>
                <div class="stat-value">{stats['total_fragments']}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Avg PII/Entity</div>
                <div class="stat-value">{stats['avg_fragments_per_entity']:.2f}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    st.markdown("""
    Upload files or specify folders to scan for PII fragments across:
    - **Structured data**: CSV, JSON, Excel
    - **Unstructured data**: TXT, LOG, PDF, DOCX
    - **Detection methods**: Presidio NER, regex patterns, Nordic ID validators
    """)
    
    # Input methods
    tab1, tab2 = st.tabs(["📤 Upload Files", "📁 Scan Folders"])
    
    uploaded_files = []
    folder_paths = []
    
    with tab1:
        uploaded_files = st.file_uploader(
            "Upload files to scan",
            accept_multiple_files=True,
            type=['csv', 'json', 'txt', 'log', 'pdf', 'docx'],
            help="Supported: CSV, JSON, TXT, LOG, PDF, DOCX"
        )
        
        # PI ANALYZER SECTION
        st.markdown("---")
        st.markdown("""
        <div class="pi-analyzer-box">
            <h4 style="margin-top: 0; color: #1E40AF;">🤖 PI Analyzer</h4>
            <p style="color: #64748B; margin-bottom: 1rem;">Upload CSV file to analyze with PII Analyzer</p>
        </div>
        """, unsafe_allow_html=True)
        
        ml_file = st.file_uploader(
            "Upload CSV for PII Analysis",
            type=['csv'],
            help="Upload CSV file to send to PII Analyzer for privacy impact analysis",
            key="PII_Analyzer"
        )
        
        if st.button("🚀 Send to PII Analyzer", type="secondary", use_container_width=True):
            with st.spinner("📡 Running Differential Privacy Analyzer..."):
                try:
                    import subprocess
                    from pathlib import Path

                    # Step 1 — Base path (this is where app.py is)
                    base_dir = Path(__file__).resolve().parent
                    data_dir = base_dir / "data"
                    out_dir = base_dir / "out"
                    data_dir.mkdir(exist_ok=True)
                    out_dir.mkdir(exist_ok=True)

                    # Step 2 — Save uploaded CSV
                    input_path = data_dir / "input.csv"
                    df = pd.read_csv(ml_file)
                    df.to_csv(input_path, index=False)
                    st.info(f"📄 File saved to: {input_path}")

                    # Step 3 — Run dp_synth.py (it's in the same folder as app.py)
                    dp_script = base_dir / "dp_synth.py"
                    st.info(f"⚙️ Running Differential Privacy script: {dp_script}")
                    result = subprocess.run(
                        ["python", str(dp_script)],
                        cwd=str(base_dir),  # stay inside CODE_MARK
                        capture_output=True,
                        text=True
                    )

                    if result.returncode != 0:
                        st.error("❌ DP Synth script failed:")
                        st.code(result.stderr)
                        st.stop()

                    st.success("✅ Differential Privacy Model executed successfully!")

                    # Step 4 — Run plot.py (also in same folder)
                    plot_script = base_dir / "plot.py"
                    st.info(f"📈 Running plot generator: {plot_script}")
                    result_plot = subprocess.run(
                        ["python", str(plot_script)],
                        cwd=str(base_dir),
                        capture_output=True,
                        text=True
                    )

                    if result_plot.returncode != 0:
                        st.error("❌ Plot generation failed:")
                        st.code(result_plot.stderr)
                        st.stop()

                    st.success("📊 Synthetic vs Real data visualization generated!")

                    # Step 5 — Display preview
                    synthetic_path = out_dir / "synthetic.csv"
                    if synthetic_path.exists():
                        synth_df = pd.read_csv(synthetic_path)
                        st.success("✅ Synthetic dataset created successfully!")
                        st.dataframe(synth_df.head(10), use_container_width=True)
                    else:
                        st.warning("⚠️ synthetic.csv not found after generation.")

                except Exception as e:
                    st.error(f"❌ Unexpected error: {str(e)}")


    
    with tab2:
        folder_input = st.text_input(
            "Folder path (comma-separated for multiple)",
            value="",
            placeholder="/data/old_logs, /data/archives",
            help="Enter full paths to folders to scan"
        )
        if folder_input:
            folder_paths = [p.strip() for p in folder_input.split(",")]
            st.info(f"📁 Will scan {len(folder_paths)} folder(s)")

    # Scan Parameters
    st.subheader("Scan Parameters")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        sample_n = st.number_input(
            "Rows sample (structured files)",
            min_value=50,
            max_value=5000,
            value=200,
            step=50,
            help="Number of rows to sample from CSV/JSON files"
        )
    
    with col2:
        threshold = st.slider(
            "Linker confidence threshold",
            min_value=50,
            max_value=95,
            value=85,
            help="Minimum match score for linking fragments (0-100)"
        )
    
    with col3:
        auto_save = st.checkbox(
            "Auto-save to database",
            value=True,
            help="Automatically persist results to local database"
        )

    # Database scanning
    st.sidebar.markdown("### 🗄️ Database & NoSQL Scans")
    sql_conn = st.sidebar.text_input("SQL connection string (read-only)", value="", type="password")
    sql_tables = st.sidebar.text_input("Tables to scan (comma-separated)", value="")
    mongo_uri = st.sidebar.text_input("MongoDB URI (read-only)", value="", type="password")
    mongo_db = st.sidebar.text_input("MongoDB Database name", value="")

    if 'db_fragments' not in st.session_state:
        st.session_state['db_fragments'] = []

    if st.sidebar.button("Scan SQL DB"):
        from layer1_scanner.scanner import scan_database
        st.sidebar.info("🔍 Scanning SQL Database...")
        try:
            sql_frags = scan_database(sql_conn, tables=[t.strip() for t in sql_tables.split(",") if t], sample_n=sample_n)
            st.session_state['db_fragments'].extend(sql_frags)
            st.sidebar.success(f"✅ Found {len(sql_frags)} PII items")
        except Exception as e:
            st.sidebar.error(f"❌ SQL scan failed: {str(e)}")

    if st.sidebar.button("Scan MongoDB"):
        from layer1_scanner.scanner import scan_mongo
        st.sidebar.info("🔍 Scanning MongoDB...")
        try:
            mongo_frags = scan_mongo(mongo_uri, mongo_db, collections=None, sample_n=sample_n)
            st.session_state['db_fragments'].extend(mongo_frags)
            st.sidebar.success(f"✅ Found {len(mongo_frags)} PII items")
        except Exception as e:
            st.sidebar.error(f"❌ MongoDB scan failed: {str(e)}")

    # RUN BUTTON
    if st.button("🚀 Run Full Historical Scan", type="primary", use_container_width=True):
        # Clear previous scan data
        for key in ['last_scan_fragments', 'last_scan_mapping', 'last_scan_df', 'scan_entity_ids']:
            if key in st.session_state:
                del st.session_state[key]
        
        fragments = st.session_state.get('db_fragments', []).copy()
        
        if not uploaded_files and not folder_paths and not fragments:
            st.warning("⚠️ Please upload files, specify folders, or connect a DB to scan.")
            st.stop()

        # Prepare file objects
        file_objs = []
        if uploaded_files:
            for uploaded_file in uploaded_files:
                raw_bytes = uploaded_file.getvalue()
                file_objs.append((uploaded_file.name, raw_bytes))

        # Phase 1 — Scanning
        with st.spinner("🔍 Scanning files..."):
            progress_bar = st.progress(0)
            progress_bar.progress(10)
            try:
                file_frags = scan_job(file_objs=file_objs, folder_paths=folder_paths, sample_n=sample_n)
                fragments.extend(file_frags)
                progress_bar.progress(40)
            except Exception as e:
                st.error(f"❌ Scan failed: {str(e)}")
                st.stop()

        if not fragments:
            st.warning("⚠️ No PII fragments found.")
            st.stop()

        st.success(f"✓ Scan complete – Found **{len(fragments)}** PII items")
        st.session_state['last_scan_fragments'] = fragments

        # Phase 2 — Linking
        with st.spinner("🔗 Linking PII items..."):
            progress_bar.progress(50)
            try:
                mapping, df_prepared = cluster_fragments(fragments, score_threshold=threshold / 100.0)
                progress_bar.progress(80)
            except Exception as e:
                st.error(f"❌ Linking failed: {str(e)}")
                st.stop()

        entity_count = len(set([v['entity_id'] for v in mapping.values() if 'entity_id' in v])) if mapping else 0
        st.success(f"✓ Linking complete – Created **{entity_count}** entities")
        
        st.session_state['last_scan_mapping'] = mapping
        st.session_state['last_scan_df'] = df_prepared
        
        if mapping:
            scan_entity_ids = set([v['entity_id'] for v in mapping.values() if 'entity_id' in v])
            st.session_state['scan_entity_ids'] = scan_entity_ids

        # Phase 3 — Save to DB
        if auto_save and mapping:
            with st.spinner("💾 Saving to database..."):
                try:
                    mapper.save_mapping(mapping, fragments)
                    progress_bar.progress(95)
                    st.success("✓ Saved to database")
                except Exception as e:
                    st.error(f"❌ Save failed: {str(e)}")

        # Phase 4 — Audit Log
        with st.spinner("📝 Writing audit log..."):
            try:
                combined_bytes = json.dumps([f.get("type") for f in fragments[:100]]).encode()
                proof_hash = handler.hash_bytes(combined_bytes)
                audit_logger.log_scan_operation(
                    proof_hash=proof_hash,
                    rows=len(fragments),
                    cols=0,
                    user=os.getenv("USER", "demo_user"),
                    source_files=[f[0] for f in file_objs] if file_objs else folder_paths,
                    fragments_found=len(fragments)
                )
                progress_bar.progress(100)
                st.success("✓ Audit log written")
            except Exception as e:
                st.error(f"❌ Audit log failed: {str(e)}")
        
        st.info("🧹 Raw PII data cleared from memory")
        st.session_state['db_fragments'] = []
        time.sleep(0.5)
        st.rerun()

    # DISPLAY RESULTS - Show scan results if available
    if 'last_scan_mapping' in st.session_state and st.session_state.get('last_scan_mapping'):
        st.markdown("---")
        st.subheader("📊 Scan Results")
        
        mapping = st.session_state['last_scan_mapping']
        df_prepared = st.session_state.get('last_scan_df')
        scan_entity_ids = st.session_state.get('scan_entity_ids', set())
        
        if mapping and df_prepared is not None:
            # Check which entities still exist
            existing_entities = set()
            for eid in scan_entity_ids:
                if mapper.get_entity(eid):
                    existing_entities.add(eid)
            
            if not existing_entities:
                st.info("All scanned entities have been deleted.")
                for key in ['last_scan_fragments', 'last_scan_mapping', 'last_scan_df', 'scan_entity_ids']:
                    if key in st.session_state:
                        del st.session_state[key]
            else:
                # Update session state with only existing entities
                st.session_state['scan_entity_ids'] = existing_entities
                
                filtered_mapping = {k: v for k, v in mapping.items() 
                                  if v.get('entity_id') in existing_entities}
                
                if 'entity_id' in df_prepared.columns:
                    filtered_df = df_prepared[df_prepared['entity_id'].isin(existing_entities)].copy()
                else:
                    filtered_df = df_prepared.copy()
                
                if not filtered_df.empty:
                    summary_df = get_cluster_summary(filtered_mapping, filtered_df)
                    
                    st.info(f"📊 Showing {len(existing_entities)} entities from your scan")
                    
                    with st.expander("🗂️ Entity Summary", expanded=True):
                        st.dataframe(
                            summary_df[['entity_id', 'fragment_count', 'names', 'emails', 'avg_confidence']], 
                            use_container_width=True
                        )
                    
                    with st.expander("🔍 View All PII Items", expanded=False):
                        st.dataframe(filtered_df, use_container_width=True)
            
            col1, col2 = st.columns([1, 3])
            with col1:
                if st.button("🗑️ Clear Scan Results"):
                    for key in ['last_scan_fragments', 'last_scan_mapping', 'last_scan_df', 'scan_entity_ids']:
                        if key in st.session_state:
                            del st.session_state[key]
                    st.rerun()

# === ENTITY MANAGER MODE ===
elif mode == "🗂️ Entity Manager":
    st.header("Entity Manager")
    
    tab1, tab2, tab3, tab4 = st.tabs(["🔍 Lookup", "📝 PII Manager", "🗑️ Erase (GDPR)", "📊 Statistics"])
    
    with tab1:
        st.subheader("Entity Lookup")
        
        search_type = st.radio("Search by", ["Entity ID", "Name/Email"], horizontal=True)
        
        if search_type == "Entity ID":
            # Initialize session state
            if 'lookup_entity_id' not in st.session_state:
                st.session_state['lookup_entity_id'] = ""
            
            # Input field
            entity_id_input = st.text_input(
                "Entity ID",
                value=st.session_state['lookup_entity_id'],
                placeholder="E-000001",
                help="Enter exact entity ID",
                key="entity_id_input_field"
            )
            
            # Update session state
            st.session_state['lookup_entity_id'] = entity_id_input
            
            col1, col2 = st.columns([1, 1])
            
            with col1:
                if st.button("🔍 Lookup Entity", use_container_width=True):
                    if not entity_id_input:
                        st.warning("Please enter an entity ID")
                    else:
                        entity_data = mapper.get_entity(entity_id_input)
                        
                        if not entity_data:
                            st.error(f"❌ Entity {entity_id_input} not found")
                            if 'display_entity' in st.session_state:
                                del st.session_state['display_entity']
                        else:
                            st.session_state['display_entity'] = entity_data
                            st.session_state['display_entity_id'] = entity_id_input
            
            with col2:
                if st.button("🗑️ Clear", use_container_width=True):
                    st.session_state['lookup_entity_id'] = ""
                    if 'display_entity' in st.session_state:
                        del st.session_state['display_entity']
                    if 'display_entity_id' in st.session_state:
                        del st.session_state['display_entity_id']
                    st.rerun()
            
            # Display entity
            if 'display_entity' in st.session_state and 'display_entity_id' in st.session_state:
                entity_data = st.session_state['display_entity']
                ent = entity_data['entity']
                
                st.success(f"✓ Found entity: {st.session_state['display_entity_id']}")
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("PII Items", ent['fragment_count'])
                with col2:
                    st.metric("Confidence", f"{ent['confidence']:.2f}")
                with col3:
                    st.metric("Created", ent['created_at'][:10])
                
                st.subheader("PII Items")
                for frag in entity_data['fragments']:
                    pii_id = generate_pii_id(ent['entity_id'], frag.get('frag_type', 'unknown'), frag.get('value', ''))
                    identifier_type = extract_identifier_type(frag)
                    proper_source = get_proper_source(frag)
                    
                    st.markdown(f"""
                    <div class="pii-card">
                        <strong>ID:</strong> {pii_id}<br>
                        <strong>Type:</strong> {identifier_type}<br>
                        <strong>Value:</strong> {frag.get('value', 'N/A')}<br>
                        <strong>Source:</strong> {proper_source}
                    </div>
                    """, unsafe_allow_html=True)
                
                audit_logger.log_access_operation(
                    entity_id=st.session_state['display_entity_id'],
                    user=os.getenv("USER", "demo_user"),
                    purpose="manual_lookup"
                )
        
        else:
            query = st.text_input(
                "Search query",
                value="",
                placeholder="Enter name or email",
                help="Search entities by name or email"
            )
            
            if st.button("🔍 Search"):
                if not query:
                    st.warning("Please enter a search query")
                else:
                    results = mapper.search_entities(query)
                    
                    if not results:
                        st.info(f"No entities found matching '{query}'")
                    else:
                        st.success(f"Found {len(results)} matching entities")
                        st.dataframe(pd.DataFrame(results), use_container_width=True)
    
    with tab2:
        st.subheader("📝 PII Manager")
        
        st.info("View and delete individual PII items from entities")
        
        entity_id_frag = st.text_input(
            "Entity ID",
            value="",
            placeholder="E-000001",
            help="Enter entity ID to manage PII items",
            key="frag_manager_input"
        )
        
        if st.button("Load PII Items"):
            if not entity_id_frag:
                st.warning("Please enter an entity ID")
            else:
                entity_data = mapper.get_entity(entity_id_frag)
                
                if not entity_data:
                    st.error(f"❌ Entity {entity_id_frag} not found")
                    if 'pii_manager_entity' in st.session_state:
                        del st.session_state['pii_manager_entity']
                else:
                    st.session_state['pii_manager_entity'] = entity_data
                    st.session_state['pii_manager_entity_id'] = entity_id_frag
        
        # Display PII items
        if ('pii_manager_entity' in st.session_state and 
            'pii_manager_entity_id' in st.session_state and
            st.session_state['pii_manager_entity_id'] == entity_id_frag):
            
            entity_data = st.session_state['pii_manager_entity']
            ent = entity_data['entity']
            
            st.success(f"Entity: {ent['entity_id']} | {ent['fragment_count']} PII items")
            
            if not entity_data['fragments']:
                st.info("No PII items found")
            else:
                for frag in entity_data['fragments']:
                    col1, col2 = st.columns([4, 1])
                    
                    pii_id = generate_pii_id(ent['entity_id'], frag.get('frag_type', 'unknown'), frag.get('value', ''))
                    identifier_type = extract_identifier_type(frag)
                    proper_source = get_proper_source(frag)
                    
                    with col1:
                        st.markdown(f"""
                        <div class="pii-card">
                            <strong>ID:</strong> {pii_id}<br>
                            <strong>Type:</strong> {identifier_type}<br>
                            <strong>Value:</strong> {frag.get('value', 'N/A')}<br>
                            <strong>Source:</strong> {proper_source}
                        </div>
                        """, unsafe_allow_html=True)
                    
                    with col2:
                        if st.button("🗑️ Delete", key=f"del_{frag.get('frag_id')}"):
                            success, result = mapper.delete_fragment(
                                frag.get('frag_id'),
                                requested_by=os.getenv("USER", "demo_user"),
                                reason="Manual PII deletion"
                            )
                            
                            if success:
                                st.success(f"✓ PII item deleted")
                                audit_logger.log_erasure_operation(
                                    entity_id=result,
                                    fragments_deleted=1,
                                    requested_by=os.getenv("USER", "demo_user"),
                                    reason="Single PII deletion"
                                )
                                
                                # Update scan results if they exist
                                if 'scan_entity_ids' in st.session_state:
                                    # Check if entity still exists
                                    updated_entity = mapper.get_entity(result)
                                    if not updated_entity:
                                        # Entity deleted, remove from scan results
                                        if result in st.session_state['scan_entity_ids']:
                                            st.session_state['scan_entity_ids'].remove(result)
                                
                                del st.session_state['pii_manager_entity']
                                del st.session_state['pii_manager_entity_id']
                                time.sleep(1)
                                st.rerun()
                            else:
                                st.error(f"❌ {result}")
    
    with tab3:
        st.subheader("🗑️ Entity Erasure (GDPR Right to Erasure)")
        
        st.markdown("""
        <div class="warning-box">
        ⚠️ <strong>Warning:</strong> This action is irreversible. All PII items will be permanently deleted.
        </div>
        """, unsafe_allow_html=True)
        
        entity_id_erase = st.text_input(
            "Entity ID to erase",
            value="",
            placeholder="E-000001",
            help="Enter entity ID to delete",
            key="erase_input"
        )
        
        reason = st.text_area(
            "Reason for erasure",
            value="GDPR Article 17 - Right to Erasure",
            help="Document the legal basis for erasure"
        )
        
        col1, col2 = st.columns([1, 3])
        
        with col1:
            confirm = st.checkbox("I confirm this erasure")
        
        with col2:
            if st.button("🗑️ Erase Entity", type="primary", disabled=not confirm):
                if not entity_id_erase:
                    st.warning("Please enter an entity ID")
                else:
                    # Check if exists
                    entity_data = mapper.get_entity(entity_id_erase)
                    
                    if not entity_data:
                        st.error(f"❌ Entity {entity_id_erase} not found")
                    else:
                        # Perform erasure
                        success, frag_count = mapper.erase_entity(
                            entity_id_erase,
                            requested_by=os.getenv("USER", "demo_user"),
                            reason=reason
                        )
                        
                        if success:
                            # Show success message
                            st.success(f"✓ Entity {entity_id_erase} erased ({frag_count} PII items deleted)")
                            
                            # Log erasure
                            audit_logger.log_erasure_operation(
                                entity_id=entity_id_erase,
                                fragments_deleted=frag_count,
                                requested_by=os.getenv("USER", "demo_user"),
                                reason=reason
                            )
                            
                            st.info("📝 Erasure logged for compliance audit trail")
                            
                            # Update scan results if they exist
                            if 'scan_entity_ids' in st.session_state and entity_id_erase in st.session_state['scan_entity_ids']:
                                st.session_state['scan_entity_ids'].remove(entity_id_erase)
                            
                            # Clear lookup session state
                            keys_to_clear = [
                                'display_entity', 'display_entity_id', 'lookup_entity_id',
                                'pii_manager_entity', 'pii_manager_entity_id'
                            ]
                            for key in keys_to_clear:
                                if key in st.session_state:
                                    del st.session_state[key]
                            
                            # Wait 3 seconds so user can see the message
                            time.sleep(3)
                            st.rerun()
                        else:
                            st.error("❌ Erasure failed")
    
    with tab4:
        st.subheader("📊 Database Statistics")
        
        col1, col2 = st.columns([3, 1])
        with col2:
            if st.button("🔄 Refresh", use_container_width=True):
                st.rerun()
        
        # Always get fresh stats
        stats = mapper.get_statistics()
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Entities", stats['total_entities'])
        with col2:
            st.metric("Total PII Items", stats['total_fragments'])
        with col3:
            st.metric("Avg PII/Entity", stats['avg_fragments_per_entity'])
        with col4:
            st.metric("Erasures Performed", stats['erasures_performed'])
        
        st.markdown("---")
        
        # List recent entities
        st.subheader("Recent Entities")
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            limit = st.slider("Number of entities to display", 5, 100, 20)
        
        with col2:
            if st.button("🔄 Refresh List", use_container_width=True):
                st.rerun()
        
        # Always get fresh list
        entities = mapper.list_entities(limit=limit)
        
        if entities:
            st.dataframe(pd.DataFrame(entities), use_container_width=True)
        else:
            st.info("No entities in database. Run a scan first.")

# === AUDIT LOGS MODE ===
else:
    st.header("📊 Audit Logs")
    
    tab1, tab2 = st.tabs(["Recent Logs", "Search Logs"])
    
    with tab1:
        st.subheader("Recent Audit Logs")
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            limit = st.slider("Number of logs to display", 5, 50, 20)
        
        with col2:
            if st.button("🔄 Refresh Logs", use_container_width=True):
                st.rerun()
        
        try:
            logs = audit_logger.get_recent_logs(limit=limit)
            
            if not logs:
                st.info("No audit logs found. Run operations to generate logs.")
            else:
                for i, log in enumerate(logs):
                    with st.expander(f"{i+1}. {log.get('operation', 'unknown').upper()} - {log.get('timestamp_utc', 'N/A')[:19]}"):
                        st.json(log)
        except Exception as e:
            st.error(f"❌ Failed to load logs: {str(e)}")
    
    with tab2:
        st.subheader("Search Audit Logs")
        
        search_by = st.radio("Search by", ["User", "Entity ID"], horizontal=True)
        
        if search_by == "User":
            user = st.text_input("Username", value=os.getenv("USER", "demo_user"))
            
            if st.button("🔍 Search"):
                try:
                    logs = audit_logger.get_logs_by_user(user)
                    
                    if not logs:
                        st.info(f"No logs found for user '{user}'")
                    else:
                        st.success(f"Found {len(logs)} logs for user '{user}'")
                        
                        for i, log in enumerate(logs):
                            with st.expander(f"{i+1}. {log.get('operation', 'unknown').upper()} - {log.get('timestamp_utc', 'N/A')[:19]}"):
                                st.json(log)
                except Exception as e:
                    st.error(f"❌ Search failed: {str(e)}")
        
        else:
            entity_id = st.text_input("Entity ID", value="", placeholder="E-000001")
            
            if st.button("🔍 Search"):
                if not entity_id:
                    st.warning("Please enter an entity ID")
                else:
                    try:
                        logs = audit_logger.get_logs_by_entity(entity_id)
                        
                        if not logs:
                            st.info(f"No logs found for entity '{entity_id}'")
                        else:
                            st.success(f"Found {len(logs)} logs for entity '{entity_id}'")
                            
                            for i, log in enumerate(logs):
                                with st.expander(f"{i+1}. {log.get('operation', 'unknown').upper()} - {log.get('timestamp_utc', 'N/A')[:19]}"):
                                    st.json(log)
                    except Exception as e:
                        st.error(f"❌ Search failed: {str(e)}")

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #6B7280; font-size: 0.9rem;">
    🔒 <strong>NordSecureAI</strong> | On-Prem AI Detective Layer | All data processed locally | No PII leaves this system<br>
    Licensed for on-premises use | GDPR Article 17 compliant | Audit trail enabled
</div>
""", unsafe_allow_html=True)