import os
import json
import logging
import httpx
from dotenv import load_dotenv
from nicegui import ui, app

# Load environment
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")

# Setup page configurations
# (Static files mapping removed)

# State variables
active_version_info = {"x_mitre_version": "Unknown", "last_updated": "Never", "entities_count": 0, "relationships_count": 0}
search_results = []
graph_nodes = []
graph_edges = []
selected_entity = None
custom_cypher_result = ""

# HTTP client with timeout settings
async def api_get(endpoint: str):
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(f"{BACKEND_URL}{endpoint}")
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"API GET {endpoint} failed: {e}")
            return None

async def api_post(endpoint: str, payload: dict):
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.post(f"{BACKEND_URL}{endpoint}", json=payload)
            if response.status_code == 200:
                return response.json()
            return {"error": response.text}
        except Exception as e:
            logger.error(f"API POST {endpoint} failed: {e}")
            return {"error": str(e)}

async def api_put_file(endpoint: str, filename: str, content: bytes):
    async with httpx.AsyncClient(timeout=120.0) as client:
        try:
            files = {'file': (filename, content, 'application/json')}
            response = await client.put(f"{BACKEND_URL}{endpoint}", files=files)
            if response.status_code in (200, 202):
                return response.json()
            return {"error": response.text}
        except Exception as e:
            logger.error(f"API PUT {endpoint} failed: {e}")
            return {"error": str(e)}

# Refresh the version metadata
async def refresh_version():
    global active_version_info
    data = await api_get("/api/v1/mitre/version")
    if data:
        active_version_info.update(data)
    else:
        active_version_info.update({
            "x_mitre_version": "None (No Ingest)",
            "last_updated": "Never",
            "entities_count": 0,
            "relationships_count": 0
        })
    # Update UI components showing version
    version_pill.set_text(f"Active MITRE: v{active_version_info['x_mitre_version']}")
    version_details.set_text(
        f"Entities: {active_version_info['entities_count']} | Relationships: {active_version_info['relationships_count']} | Last Ingest: {active_version_info['last_updated']}"
    )

# Page Layout configuration
ui.query('.q-page').classes('bg-slate-950 text-slate-100')
ui.query('body').classes('bg-slate-950')

# NiceGUI Styling Tweaks
ui.dark_mode().enable()

# Cytoscape Graph Visualization renderer
def get_cytoscape_html(nodes, edges) -> str:
    """
    Generates a Cytoscape.js HTML/JS representation for interactive rendering.
    """
    cy_nodes = []
    cy_edges = []
    
    # Node colors based on type
    color_map = {
        "attack-pattern": "#ef4444",      # Red
        "course-of-action": "#22c55e",    # Green
        "intrusion-set": "#ec4899",       # Pink
        "malware": "#eab308",             # Yellow
        "tool": "#a855f7",                # Purple
        "x-mitre-tactic": "#3b82f6"       # Blue
    }

    for n in nodes:
        label = n.get("mitre_id") or n.get("type", "")
        name = n.get("name", "")
        truncated_name = name[:20] + "..." if len(name) > 20 else name
        bg_color = color_map.get(n.get("type", ""), "#64748b")
        
        cy_nodes.append({
            "data": {
                "id": n["id"],
                "label": f"{label}\n{truncated_name}",
                "fullName": name,
                "type": n.get("type", ""),
                "mitre_id": n.get("mitre_id", ""),
                "color": bg_color
            }
        })

    for e in edges:
        cy_edges.append({
            "data": {
                "id": e["id"],
                "source": e["source"],
                "target": e["target"],
                "label": e["type"]
            }
        })

    elements_json = json.dumps(cy_nodes + cy_edges)

    return f"""
    <div id="cy" style="width: 100%; height: 500px; border-radius: 8px; background-color: #0f172a; border: 1px solid #334155;"></div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.26.0/cytoscape.min.js"></script>
    <script>
        setTimeout(function() {{
            var cy = cytoscape({{
                container: document.getElementById('cy'),
                elements: {elements_json},
                style: [
                    {{
                        selector: 'node',
                        style: {{
                            'background-color': 'data(color)',
                            'label': 'data(label)',
                            'color': '#f8fafc',
                            'font-size': '10px',
                            'text-wrap': 'wrap',
                            'text-valign': 'center',
                            'text-halign': 'center',
                            'width': '65px',
                            'height': '65px',
                            'border-width': '2px',
                            'border-color': '#1e293b'
                        }}
                    }},
                    {{
                        selector: 'edge',
                        style: {{
                            'width': 2,
                            'line-color': '#475569',
                            'target-arrow-color': '#475569',
                            'target-arrow-shape': 'triangle',
                            'curve-style': 'bezier',
                            'label': 'data(label)',
                            'color': '#94a3b8',
                            'font-size': '8px',
                            'text-rotation': 'autorotate',
                            'text-background-opacity': 0.8,
                            'text-background-color': '#0f172a',
                            'text-background-padding': '3px',
                            'text-background-shape': 'roundrectangle'
                        }}
                    }}
                ],
                layout: {{
                    name: 'cose',
                    idealEdgeLength: 100,
                    nodeOverlap: 20,
                    refresh: 20,
                    fit: true,
                    padding: 30,
                    randomize: false,
                    componentSpacing: 100,
                    nodeRepulsion: 400000,
                    edgeElasticity: 100,
                    nestingFactor: 5,
                    gravity: 80,
                    numIter: 1000,
                    initialTemp: 200,
                    coolingFactor: 0.95,
                    minTemp: 1.0
                }}
            }});
            
            cy.on('tap', 'node', function(evt){{
                var nodeData = evt.target.data();
                // Send back to NiceGUI via console log / custom event or display tooltip
                alert("Entity: " + nodeData.fullName + " (" + nodeData.mitre_id + ")\\nType: " + nodeData.type);
            }});
        }}, 200);
    </script>
    """

# ----------------- UI Builders -----------------

# Header Section
with ui.row().classes('w-full items-center justify-between p-4 bg-slate-900 border-b border-indigo-900 shadow-md'):
    with ui.row().classes('items-center gap-3'):
        ui.icon('shield', color='indigo-400').classes('text-3xl animate-pulse')
        ui.label('MITRE ATT&CK AI Platform').classes('text-2xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-cyan-400')
    with ui.row().classes('items-center gap-4'):
        version_pill = ui.label('Active MITRE: loading...').classes('bg-indigo-950 text-indigo-300 border border-indigo-800 px-3 py-1 rounded-full text-sm font-semibold')
        version_details = ui.label('').classes('text-xs text-slate-400')

# Main Tabs Setup
with ui.tabs().classes('w-full bg-slate-900 border-b border-indigo-950') as tabs:
    search_tab = ui.tab('Semantic Search', icon='search')
    graph_tab = ui.tab('Graph Explorer', icon='hub')
    ingest_tab = ui.tab('Data Ingestion', icon='cloud_upload')

with ui.tab_panels(tabs, value=search_tab).classes('w-full bg-transparent p-6'):
    
    # 1. Semantic Search Tab
    with ui.tab_panel(search_tab).classes('gap-4'):
        with ui.row().classes('w-full gap-4 items-center'):
            search_input = ui.input(
                placeholder='Search using natural language (e.g. "Credential dumping on Windows systems")',
                on_change=lambda: None
            ).classes('grow bg-slate-900 border border-slate-800 rounded-lg p-2').props('dark filled')
            
            entity_filter = ui.select(
                options={
                    "": "All Types",
                    "attack-pattern": "Technique",
                    "course-of-action": "Mitigation",
                    "intrusion-set": "Threat Group",
                    "malware": "Malware",
                    "tool": "Tool",
                    "x-mitre-tactic": "Tactic"
                },
                value=""
            ).classes('w-48').props('dark outline')
            
            search_limit = ui.number('Limit', value=10, min=1, max=50).classes('w-20').props('dark outline')
            
            search_button = ui.button('Search', icon='travel_explore', on_click=lambda: trigger_search()).classes('bg-gradient-to-r from-indigo-600 to-cyan-600')

        # Results area
        results_container = ui.column().classes('w-full gap-4 mt-6')

    # 2. Graph Explorer Tab
    with ui.tab_panel(graph_tab).classes('gap-4'):
        with ui.row().classes('w-full gap-4 items-start'):
            # Left panel for queries
            with ui.card().classes('w-80 bg-slate-900 border border-slate-800 p-4 shrink-0'):
                ui.label('Query MITRE Graph').classes('text-lg font-bold text-indigo-400')
                mitre_id_input = ui.input('MITRE Entity ID', placeholder='e.g., T1059 or T1078').classes('w-full').props('dark')
                depth_slider = ui.slider(min=1, max=4, value=2).classes('w-full')
                ui.label('Traversal Depth').classes('text-xs text-slate-400')
                
                ui.button('Load Lineage', icon='family_history', on_click=lambda: load_lineage_graph()).classes('w-full bg-indigo-600 mt-2')
                
                ui.separator().classes('my-4 border-slate-800')
                
                ui.label('Raw Cypher Query').classes('text-sm font-bold text-slate-400')
                cypher_input = ui.textarea(
                    placeholder='MATCH (n:Malware)-[r:USES]->(t:AttackPattern) RETURN n.name, t.name LIMIT 5'
                ).classes('w-full text-xs font-mono').props('dark')
                ui.button('Execute Cypher', icon='bolt', on_click=lambda: run_custom_cypher()).classes('w-full bg-cyan-600 mt-2')

            # Right panel for Visual Representation
            with ui.column().classes('grow bg-slate-900 border border-slate-800 rounded-lg p-4 min-h-[550px]'):
                ui.label('Interactive Relationship Visualizer').classes('text-lg font-bold text-indigo-400')
                graph_visualizer = ui.html('').classes('w-full')
                
                # Cypher results table placeholder
                cypher_result_card = ui.card().classes('w-full bg-slate-950 p-4 border border-slate-800 font-mono text-xs hidden')
                cypher_output = ui.html('')

    # 3. Data Ingestion Tab
    with ui.tab_panel(ingest_tab).classes('gap-4'):
        with ui.row().classes('w-full gap-6'):
            # Ingestion controller card
            with ui.card().classes('w-1/2 bg-slate-900 border border-slate-800 p-6'):
                ui.label('Dataset Lifecycle Manager').classes('text-xl font-bold text-indigo-400')
                ui.label('Upload a STIX 2.1 JSON file (Enterprise ATT&CK bundle) to update vectors and graph data.').classes('text-slate-400 text-sm mb-4')
                
                version_upload_input = ui.input('MITRE Version', placeholder='e.g., 14.1').classes('w-full mb-4').props('dark')
                
                ui.label('Select MITRE JSON File').classes('text-sm font-semibold text-slate-300')
                uploader = ui.upload(
                    label='Drop STIX JSON here', 
                    multiple=False, 
                    auto_upload=False,
                    on_upload=lambda e: handle_upload(e)
                ).classes('w-full border-dashed border-indigo-900 bg-slate-950 rounded-lg').props('dark')
                
                ui.button('Download Current Active Dataset', icon='download', on_click=lambda: ui.download(f"{BACKEND_URL}/api/v1/mitre")).classes('w-full bg-emerald-700 mt-4')

            # Ingestion log & status card
            with ui.card().classes('w-1/2 bg-slate-900 border border-slate-800 p-6'):
                ui.label('Pipeline Status').classes('text-xl font-bold text-indigo-400')
                
                status_spinner = ui.spinner(size='lg').classes('hidden my-4')
                status_label = ui.label('Idle. Ready for data ingestion.').classes('text-slate-200 font-semibold my-2')
                
                progress_container = ui.column().classes('w-full gap-2 mt-4')
                ui.button('Check Status', icon='sync', on_click=lambda: check_ingestion_status()).classes('bg-indigo-600')

# ----------------- UI Interactivity Logic -----------------

async def trigger_search():
    query = search_input.value
    if not query:
        ui.notify("Please enter a query string.", type='warning')
        return
        
    results_container.clear()
    with results_container:
        spinner = ui.spinner(size='lg', color='indigo-500').classes('self-center my-6')
        
    payload = {
        "query": query,
        "limit": int(search_limit.value),
        "entity_type": entity_filter.value if entity_filter.value else None
    }
    
    results = await api_post("/api/v1/mitre/search", payload)
    
    results_container.clear()
    if not results or "error" in results:
        with results_container:
            ui.label(f"Search failed. Make sure backend is running. Details: {results.get('error') if results else 'Timeout'}").classes('text-red-400 font-semibold')
        return

    if not results:
        with results_container:
            ui.label("No matches found.").classes('text-slate-400 italic')
        return

    with results_container:
        for r in results:
            score_pct = int(r["score"] * 100) if r.get("score") else 50
            # Set color according to score
            badge_color = "bg-emerald-950 text-emerald-300 border-emerald-800" if score_pct > 70 else "bg-amber-950 text-amber-300 border-amber-800"
            
            with ui.card().classes('w-full bg-slate-900 border border-slate-800 p-4 hover:border-indigo-600 transition-all rounded-lg shadow'):
                with ui.row().classes('w-full justify-between items-start'):
                    with ui.column().classes('gap-1'):
                        with ui.row().classes('items-center gap-2'):
                            ui.label(f"[{r.get('mitre_id', 'N/A')}]").classes('text-indigo-400 font-mono font-bold text-lg')
                            ui.label(r["name"]).classes('text-lg font-bold text-slate-100')
                        ui.label(r["type"].replace("-", " ").title()).classes('text-xs font-semibold px-2 py-0.5 bg-slate-800 text-slate-300 rounded')
                    with ui.row().classes('items-center gap-3'):
                        ui.label(f"Match Similarity: {score_pct}%").classes(f"text-xs px-2.5 py-1 rounded-full border font-semibold {badge_color}")
                        ui.button('Graph Lineage', icon='hub', on_click=lambda val=r.get("mitre_id"): select_for_graph(val)).classes('bg-indigo-600 text-xs py-0.5')
                
                # Truncated description
                desc = r.get("description", "No description provided.")
                ui.label(desc).classes('text-sm text-slate-400 mt-2 line-clamp-3')

def select_for_graph(mitre_id):
    if not mitre_id:
        ui.notify("Entity has no MITRE ID for graph exploration", type='warning')
        return
    mitre_id_input.value = mitre_id
    tabs.value = graph_tab
    load_lineage_graph()

async def load_lineage_graph():
    mitre_id = mitre_id_input.value
    if not mitre_id:
        ui.notify("Please enter a MITRE ID (e.g. T1059)", type='warning')
        return
        
    graph_visualizer.set_content("<div class='p-4 text-slate-400 animate-pulse'>Loading lineage graph relations from Neo4j...</div>")
    cypher_result_card.classes(add='hidden')

    payload = {
        "mitre_id": mitre_id,
        "depth": int(depth_slider.value)
    }
    
    data = await api_post("/api/v1/mitre/lineage", payload)
    
    if not data or "error" in data or not data.get("nodes"):
        graph_visualizer.set_content(
            f"<div class='p-4 text-red-400 font-semibold'>"
            f"No relationship lineage found for ID '{mitre_id}' in Neo4j. Ingest dataset first or select another entity."
            f"</div>"
        )
        return
        
    html_content = get_cytoscape_html(data["nodes"], data["edges"])
    graph_visualizer.set_content(html_content)

async def run_custom_cypher():
    query = cypher_input.value
    if not query:
        ui.notify("Please enter a Cypher query.", type='warning')
        return
        
    cypher_result_card.classes(remove='hidden')
    cypher_output.set_content("<div class='animate-pulse'>Executing query on Neo4j...</div>")
    
    payload = {
        "query": query
    }
    
    data = await api_post("/api/v1/mitre/query", payload)
    
    if not data or "error" in data:
        cypher_output.set_content(f"<span class='text-red-400'>Error: {data.get('error') if data else 'Unknown connection issue'}</span>")
        return
        
    records = data.get("records", [])
    if not records:
        cypher_output.set_content("<span class='text-slate-400 italic'>Query successfully executed. No records returned.</span>")
        return
        
    # Render pretty JSON table
    html_tbl = "<table class='w-full text-left border-collapse border border-slate-800 text-xs'>"
    # Header
    html_tbl += "<thead><tr class='bg-slate-900 text-slate-300'>"
    keys = list(records[0].keys())
    for k in keys:
        html_tbl += f"<th class='p-2 border border-slate-800'>{k}</th>"
    html_tbl += "</tr></thead><tbody>"
    # Rows
    for r in records:
        html_tbl += "<tr class='hover:bg-slate-900'>"
        for k in keys:
            val = r.get(k)
            # Shorten if dict
            if isinstance(val, dict):
                val_str = val.get("name") or val.get("id") or json.dumps(val)[:30]
            else:
                val_str = str(val)
            html_tbl += f"<td class='p-2 border border-slate-800 text-slate-400'>{val_str}</td>"
        html_tbl += "</tr>"
    html_tbl += "</tbody></table>"
    
    cypher_output.set_content(html_tbl)

async def handle_upload(e):
    version = version_upload_input.value
    if not version:
        ui.notify("Please specify a version name (e.g. 14.1) before uploading.", type='warning')
        return

    file_name = e.name
    file_content = e.content.read()
    
    status_label.set_text("Uploading file and starting ingestion...")
    status_spinner.classes(remove='hidden')
    
    result = await api_put_file(f"/api/v1/mitre/{version}", file_name, file_content)
    
    if "error" in result:
        status_label.set_text(f"Upload failed: {result['error']}")
        status_spinner.classes(add='hidden')
        ui.notify(f"Ingestion failed: {result['error']}", type='negative')
    else:
        status_label.set_text("In progress. Ingestion task scheduled in backend.")
        ui.notify("File uploaded. Check status for background completion.", type='positive')
        # Start checking status automatically
        await check_ingestion_status()

async def check_ingestion_status():
    status_spinner.classes(remove='hidden')
    result = await api_get("/api/v1/mitre/ingestion-status")
    
    if not result:
        status_label.set_text("Could not connect to backend.")
        status_spinner.classes(add='hidden')
        return
        
    status = result.get("status", "unknown")
    msg = result.get("message", "")
    
    if status == "processing":
        status_label.set_text(f"Processing: {msg}")
        status_spinner.classes(remove='hidden')
    elif status == "completed":
        status_label.set_text(
            f"Success: {msg}\n"
            f"Entities imported: {result.get('entities_imported', 0)}\n"
            f"Relationships imported: {result.get('relationships_imported', 0)}"
        )
        status_spinner.classes(add='hidden')
        # Refresh current active version pill
        await refresh_version()
    elif status == "failed":
        status_label.set_text(f"Failed: {msg}\nError: {result.get('error', '')}")
        status_spinner.classes(add='hidden')
    else:
        status_label.set_text(f"Idle: {msg}")
        status_spinner.classes(add='hidden')

# Run refresh metadata on startup
app.on_startup(refresh_version)

# Start NiceGUI application
ui.run(
    host="0.0.0.0",
    port=8080,
    title="MITRE ATT&CK AI Platform",
    show=False # Running inside docker container, no need to open local browser immediately
)
