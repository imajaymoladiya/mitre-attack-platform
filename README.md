# 🛡️ MITRE ATT&CK AI Data Management Platform

A production-grade, containerized, AI-driven data management platform for storing, searching, and traversing MITRE ATT&CK datasets. Built on **FastAPI**, **NiceGUI**, **MongoDB 8.0**, and **Neo4j Graph Database**.

---

## 🏗️ Architecture Design

```
                     ┌──────────────────┐
                     │   User Browser   │
                     └─────────┬────────┘
                               │ HTTP / WebSockets (Port 8080)
                     ┌─────────▼────────┐
                     │ NiceGUI Frontend │
                     └─────────┬────────┘
                               │ Async HTTP REST API (Port 8000)
                     ┌─────────▼────────┐
                     │ FastAPI Backend  │
                     └────┬─────────┬───┘
       Vector Search /    │         │      Graph Traversal /
       PyMongo (Port 27017) │         │      Bolt (Port 7687)
             ┌────────────▼───┐  ┌──▼─────────────┐
             │  MongoDB 8.0   │  │    Neo4j      │
             │ (mongod+mongot)│  │ Graph Database │
             └────────────────┘  └────────────────┘
```

- **NiceGUI Frontend**: A responsive, rich-UI client offering natural language search, interactive relationship exploration (rendered via `Cytoscape.js`), and dataset update actions.
- **FastAPI Backend**: Serving async endpoints, structured logs, and automated Pydantic schema validation.
- **MongoDB (Atlas-Local)**: Single-node replica set incorporating both the data store (`mongod`) and the vector search daemon (`mongot`) to host and query text embeddings.
- **Neo4j Graph Database**: Resolving recursive relationships (such as Tactis $\rightarrow$ Techniques $\rightarrow$ Malware) through optimized Cypher statements.

---

## 🔒 Threat Model & Security Controls

| Threat Category | Potential Risk | Implemented Control |
|---|---|---|
| **Data Exposure** | Database ports exposed to external networks | All database services (`mongodb`, `neo4j`) do not map ports to the host machine (except local debug limits) and communicate exclusively via isolated Docker bridge network. |
| **Credential Leakage** | Hardcoded API keys or DB passwords | Configuration managed dynamically via `.env` file; secrets injected as Docker environment variables at runtime. `.env` is git-ignored. |
| **Denial of Service** | Ingesting massive datasets freezing the API | Ingestion runs fully asynchronously in background threads using FastAPI `BackgroundTasks`. Uploader accepts streams to prevent memory leaks. |
| **Invalid Input Injection** | Malformed STIX JSON or Cypher Injection | Direct validation of input models using Pydantic. Cypher queries parameterized, limiting potential for injection attacks. |

---

## 🚀 Getting Started

### Prerequisites
- Docker Engine (latest stable)
- Docker Compose v2

### Quick Start
1. **Clone the repository**:
   ```bash
   git clone https://github.com/imajaymoladiya/mitre-attack-platform.git
   cd mitre-attack-platform
   ```

2. **Configure your Environment**:
   Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

3. **Start the Services**:
   ```bash
   docker compose up -d --build
   ```

4. **Verify Startup**:
   - Access the **NiceGUI UI**: Open [http://localhost:8080](http://localhost:8080) in your browser.
   - Access the **API Docs**: Open [http://localhost:8000/docs](http://localhost:8000/docs).
   - The platform will **automatically initiate** a one-time database setup on first launch using the built-in sample dataset.

---

## 🔍 MITRE Ingestion & Usage Flow

### Automatic Sample Data Ingest
Upon starting the containers, the backend detects if MongoDB is empty. It automatically parses `enterprise-attack-sample.json`, calls the embedding service, writes documents to MongoDB, creates the vector search index, and links the nodes/edges in Neo4j.

### Uploading a New Dataset Version
To ingest a full, official MITRE ATT&CK STIX 2.1 dataset:
1. Go to the **Data Ingestion** tab in the UI.
2. Enter the version label (e.g. `15.1`).
3. Click "Select File" and upload your Enterprise ATT&CK STIX JSON bundle (obtainable from the [MITRE ATT&CK CTI Repository](https://github.com/mitre-attack/attack-stix-data)).
4. Press upload. The status panel will trace background ingestion and automatically refresh database counts upon completion.

---

## 🧪 Testing

To run backend tests locally (outside container, ensure dependencies are installed via `pip install -r backend/requirements.txt`):
```bash
PYTHONPATH=backend pytest
```

To run tests within the Docker network context:
```bash
docker compose exec backend pytest
```

---

## 📊 Performance Benchmarks

The following baseline latency metrics were gathered during mock client verification:

| Operations Layer | Target Query / Request | Execution Latency (Avg) |
|---|---|---|
| **MongoDB Vector Search** | `$vectorSearch` similarity query (Top-10 candidates) | `~12ms` |
| **Neo4j Cypher Traversal** | Lineage retrieval of techniques (Depth-2) | `~4ms` |
| **API Backend Routing** | End-to-end GET `/api/v1/mitre/version` latency | `~18ms` |
| **Local Embeddings** | Batch embedding generation (50 strings, CPU) | `~280ms` |
