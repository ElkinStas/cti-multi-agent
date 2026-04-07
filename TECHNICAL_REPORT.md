# CTI Multi-Agent System — Technical Report

## 1. System overview

The Cyber Threat Intelligence Agent System is a multi-agent pipeline that automates the discovery, extraction, enrichment, and reporting of cybersecurity incidents. It accepts a free-text query (e.g., "MOVEit vulnerability exploitation", "Clop ransomware campaigns"), searches the open web for relevant articles, extracts structured intelligence from unstructured text, enriches referenced CVEs with data from the NVD API, and produces a consolidated JSON + Markdown report — all exposed through an async REST API.

### High-level data flow

```
User query
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│                    FastAPI (app/main.py)                      │
│   POST /search → asyncio.create_task → background pipeline   │
│   GET  /search/{id}/status → poll run state                  │
│   GET  /search/{id}/report → retrieve final report           │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│              LangGraph Orchestrator (orchestrator.py)         │
│              StateGraph DAG with typed AgentState             │
│                                                              │
│   ┌──────────┐   ┌────────────┐   ┌──────────────────┐       │
│   │  Search   │──▶│ Extraction │──▶│ Post-Processing  │       │
│   │  Agent    │   │   Agent    │   │     Agent        │       │
│   └──────────┘   └────────────┘   └───────┬──────────┘       │
│                                           │                  │
│   ┌──────────────────┐   ┌────────────┐   │                  │
│   │  Report Builder  │◀──│   Report   │◀──┘                  │
│   │  (pure function) │   │   Agent    │◀── CVE Enrichment    │
│   └───────┬──────────┘   └────────────┘       Agent          │
│           │                                                  │
└───────────┼──────────────────────────────────────────────────┘
            │
            ▼
┌──────────────────────────────────────────────────────────────┐
│              InMemoryRunStore (store.py)                      │
│              status: PENDING → RUNNING → COMPLETED           │
│              report: JSON + Markdown + Telemetry              │
└──────────────────────────────────────────────────────────────┘
            │
            ▼
      Streamlit UI (ui/app.py)  ←── polls API, renders report
```

### Technology stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| API framework | FastAPI | Async REST endpoints, request validation, background tasks |
| Orchestration | LangGraph (StateGraph) | DAG-based agent coordination with typed state |
| LLM provider | Anthropic Claude (primary), Ollama (alternative) | Structured extraction + report synthesis |
| HTTP client | httpx | All outbound HTTP with retry/backoff/jitter |
| Data validation | Pydantic v2 | Models, serialization, API schemas |
| CVE data | NVD API v2.0 | Vulnerability enrichment |
| Web discovery | DuckDuckGo HTML + Google News RSS | Two independent search channels |
| Caching | In-memory SimpleCache | NVD responses (24h TTL), LLM responses (1h TTL) |
| UI | Streamlit | Interactive dashboard with tabs |
| Testing | pytest | 42 tests, no network/API keys required |
| Containerization | Docker + docker-compose | API + UI services |

---

## 2. Architecture deep dive

### 2.1 Agent pipeline (LangGraph DAG)

```
START
  │
  ▼
search_agent ──────────── Discovers articles from web
  │                       Input:  SearchRequest (query, time_range, max_articles)
  │                       Output: list[SearchResult]
  ▼
extraction_agent ──────── Extracts structured incidents
  │                       Input:  list[SearchResult]
  │                       Output: list[Incident]
  ▼
postprocess_agent ──────── Cleans, deduplicates, validates
  │                        Input:  list[Incident] + query
  │                        Output: list[Incident] (cleaned)
  ▼
cve_enrichment_agent ───── Fetches CVE details from NVD
  │                        Input:  list[Incident]
  │                        Output: list[Vulnerability]
  ▼
report_agent ──────────── Synthesizes analysis
  │                       Input:  list[Incident] + list[Vulnerability] + query
  │                       Output: dict (executive_summary, key_findings, recommendations)
  ▼
report_builder ────────── Assembles final report (pure function)
  │                       Input:  all of the above + telemetry + warnings
  │                       Output: Report (JSON + Markdown + metrics)
  ▼
 END
```

Each node is wrapped in `_timed_node()` which provides:
- Per-node telemetry recording (started_at, finished_at, duration_ms, items_in, items_out)
- Bounded retry (1 additional attempt, only for transient/transport errors)
- Graceful degradation (safe fallback + warning on failure)

### 2.2 Async execution model

```
FastAPI event loop (async)
    │
    │  POST /search
    │  ├── create run in InMemoryRunStore (PENDING)
    │  ├── asyncio.create_task(_execute_run)
    │  └── return 202 + run_id
    │
    │  Background task:
    │  ├── set status = RUNNING
    │  ├── orchestrator.run(request, run_id)
    │  │       │
    │  │       ▼
    │  │   LangGraph.ainvoke(initial_state)
    │  │       │
    │  │       ├── Dispatches sync node functions into
    │  │       │   ThreadPoolExecutor (LangGraph built-in)
    │  │       │
    │  │       ├── search_agent._search_duckduckgo()     ← blocking HTTP (in thread)
    │  │       ├── search_agent._hydrate_candidate()     ← blocking HTTP (in thread)
    │  │       ├── extraction_agent.generate_json()      ← blocking HTTP (in thread)
    │  │       ├── enrichment_agent._fetch_cve()         ← blocking HTTP (in thread)
    │  │       │
    │  │       └── Event loop NOT blocked
    │  │
    │  ├── set status = COMPLETED + store report
    │  └── (or set status = FAILED + store error)
    │
    │  GET /search/{id}/status → poll
    │  GET /search/{id}/report → retrieve
```

### 2.3 Retry and fault tolerance

```
Layer 1: HTTP transport (app/clients.py)
    ├── Retry on: 429, 500, 502, 503, 504, TimeoutException, ConnectError
    ├── Max retries: 3
    ├── Backoff: exponential with jitter (0.5s base, 8s max)
    └── Non-retryable: 4xx (except 429), parse errors

Layer 2: Orchestrator node (app/orchestrator.py)
    ├── Retry budget: 1 additional attempt per node
    ├── Retry only: httpx.TimeoutException, ConnectError, RemoteProtocolError,
    │               ConnectionError, TimeoutError, OSError
    ├── NOT retried: ValueError, KeyError, json.JSONDecodeError, ValidationError
    │                (deterministic failures that would repeat identically)
    └── On exhaustion: return safe fallback, record warning + degraded telemetry
```

### 2.4 Caching

```
┌─────────────────────────────────┐
│     SimpleCache (app/cache.py)  │
│     Thread-safe, per-key TTL    │
│     In-memory dict + Lock       │
├─────────────────────────────────┤
│                                 │
│  nvd_cache (24h TTL)            │
│    key: "nvd:{cve_id}"          │
│    value: Vulnerability dict    │
│    saves: redundant NVD calls   │
│           across runs + within  │
│           runs with overlapping │
│           CVE sets              │
│                                 │
│  llm_cache (1h TTL)             │
│    key: sha256(model+system     │
│          +user prompt)          │
│    value: parsed JSON dict      │
│    saves: identical extraction  │
│           or synthesis prompts  │
│                                 │
└─────────────────────────────────┘
```

---

## 3. Module-by-module reference

### 3.1 `app/config.py` — Settings

Reads all configuration from environment variables at startup. Optional `python-dotenv` integration loads `.env` file for local development. Frozen dataclass ensures immutability after initialization.

| Setting | Default | Purpose |
|---------|---------|---------|
| `ANTHROPIC_API_KEY` | None | Enables LLM extraction + synthesis |
| `ANTHROPIC_EXTRACTION_MODEL` | claude-haiku-4-20250414 | Cheap model for structured extraction |
| `ANTHROPIC_REPORT_MODEL` | claude-sonnet-4-20250514 | Strong model for report synthesis |
| `ANTHROPIC_BASE_URL` | None | Custom API endpoint (proxy) |
| `OLLAMA_BASE_URL` | http://127.0.0.1:11434 | Ollama server |
| `OLLAMA_MODEL` | None | Enables Ollama path |
| `DEFAULT_MAX_ARTICLES` | 5 | Used as Pydantic default for SearchRequest |
| `MAX_LLM_CHARS_PER_ARTICLE` | 8000 | Prompt budget per article |
| `REQUEST_TIMEOUT_SECONDS` | 20 | HTTP client timeout |

Cost optimization: extraction uses haiku (cheap, fast, good enough for structured JSON), report synthesis uses sonnet (stronger reasoning for narrative quality).

---

### 3.2 `app/clients.py` — HTTP client

Single `httpx.Client` wrapper used by all agents. Features:
- Follow redirects enabled
- Configurable User-Agent
- Retry loop with exponential backoff + jitter for transient errors
- Retryable status codes: 429, 500, 502, 503, 504
- Retryable exceptions: TimeoutException, ConnectError
- Non-retryable: all other HTTPStatusError (immediate raise)
- Structured logging on each retry attempt

All outbound HTTP in the system goes through this client — no mixed urllib/httpx.

---

### 3.3 `app/cache.py` — In-memory TTL cache

Thread-safe cache with per-key expiry. Two module-level singletons:
- `nvd_cache` — CVE enrichment results (24h TTL)
- `llm_cache` — LLM JSON responses (1h TTL)

`prompt_cache_key(system, user, model)` → deterministic SHA-256 hash.

Lazy eviction: expired entries are removed on next `get()` call, not proactively.

Production swap: replace `SimpleCache` with Redis client implementing the same `get/set/has` interface.

---

### 3.4 `app/llm.py` — LLM abstraction

Unified entry point for all LLM calls. Provider chain:
1. Anthropic Claude (if `ANTHROPIC_API_KEY` set and `anthropic` package installed)
2. Ollama (if `OLLAMA_MODEL` set)
3. None (triggers heuristic fallback in calling agent)

Features:
- Lazy import of `anthropic` package (optional dependency)
- LLM response caching via `llm_cache`
- Accepts `model` parameter so callers can specify extraction vs. synthesis model
- Structured logging on cache hits and LLM calls
- On failure: logs `provider`, `model`, `error` type, and first 200 chars of detail (not silent `return None`)
- Bare `except Exception` returns None → agent falls back to heuristics

---

### 3.5 `app/models.py` — Pydantic models

All data types in one place. Key models:

```
SearchRequest
  ├── query: str (min_length=3, stripped, whitespace-only rejected via field_validator)
  ├── time_range: str | None
  └── max_articles: int (default from config, 1-10)

SearchResult
  ├── title, url (HttpUrl), snippet
  ├── published_at: datetime | None
  └── raw_text: str

Incident
  ├── name, date, affected_organization
  ├── attack_vector, malware_family
  ├── software_involved: list[str]
  ├── iocs: list[str]
  ├── cve_ids: list[str]
  ├── related_vulnerabilities: list[IncidentCVERef]  ← hydrated in build_report
  ├── source_url, source_title, source_summary
  └── (no processing logic — pure data)

IncidentCVERef (lightweight)
  ├── cve_id, description
  ├── cvss_score, severity
  └── (embedded inside Incident for direct inspection)

Vulnerability (full)
  ├── cve_id, description
  ├── cvss_score, severity
  ├── affected_products: list[str]
  ├── references: list[str]
  └── known_exploited: bool | None

NodeTelemetry
  ├── node, started_at, finished_at, duration_ms
  ├── items_in, items_out, attempt
  ├── degraded: bool
  └── error: str | None

Report
  ├── query, generated_at
  ├── incidents: list[Incident]
  ├── vulnerabilities: list[Vulnerability]
  ├── summary_stats, quality_metrics, evaluation_metrics
  ├── executive_summary, key_findings, recommendations
  ├── markdown_summary
  ├── pipeline_telemetry: list[NodeTelemetry]
  └── warnings: list[str]
```

---

### 3.6 `app/main.py` — FastAPI application

Four endpoints:

| Method | Path | Status | Description |
|--------|------|--------|-------------|
| POST | /search | 202 | Submit query, get run_id |
| GET | /search/{run_id}/status | 200/404 | Poll run state |
| GET | /search/{run_id}/report | 200/404/409 | Retrieve final report (response_model=Report) |
| GET | /health | 200 | Liveness probe |

Async lifecycle: POST creates run → `asyncio.create_task` launches background pipeline → client polls status → retrieves report on completion.

---

### 3.7 `app/store.py` — Run store

`InMemoryRunStore`: async dict + asyncio.Lock. Four methods:
- `create(run_id, request)` → RunState (PENDING)
- `get(run_id)` → RunState | None
- `set_status(run_id, status, error?)` → updates state
- `set_report(run_id, report)` → sets COMPLETED + stores report

Limitations: not durable across restarts, not multi-worker safe. Interface designed for drop-in Redis/Postgres replacement.

---

### 3.8 `app/orchestrator.py` — LangGraph DAG

`ThreatIntelOrchestrator`: builds a `StateGraph` with 6 nodes and linear edges. `AgentState` TypedDict carries shared state through the graph.

Core mechanism — `_timed_node(node_name, state, fn, fallback, items_in)`:
1. Start timer
2. Execute `fn()` (the agent's `.run()` call)
3. On success: record NodeTelemetry, log structured event, return result
4. On transient error + budget remaining: log retry, loop
5. On deterministic error or budget exhausted: execute `fallback()`, record degraded telemetry, add warning, continue pipeline

`_is_retryable(exc)` classifies errors:
- Retryable: httpx.TimeoutException, ConnectError, RemoteProtocolError, ConnectionError, TimeoutError, OSError
- Not retryable: everything else (ValueError, KeyError, ValidationError, etc.)

`_count_items(node_name, result)` returns items_out for telemetry — checks for `search_results`, `incidents`, `vulnerabilities`, or `analysis` keys.

`report_builder` node has inline timing (not wrapped in `_timed_node` since it's a pure function that shouldn't fail or retry).

---

### 3.9 `app/agents/search.py` — SearchAgent

The most complex agent. Responsible for web discovery, article hydration, relevance scoring, and time-range filtering.

```
SearchAgent.run(request)
    │
    ├── Build search query (query + time_range + cyber keywords)
    │
    ├── Discovery (two independent channels, fault-isolated):
    │   ├── _search_duckduckgo() → HTML scraping with regex
    │   └── _search_google_news() → RSS XML parsing
    │
    ├── Merge + deduplicate candidates
    │
    ├── Parallel hydration (ThreadPoolExecutor, 4 workers):
    │   └── _hydrate_candidate() per URL:
    │       ├── Fetch full HTML
    │       ├── Extract canonical URL
    │       ├── Extract title from <title>
    │       ├── Extract meta description
    │       ├── Extract published_at from meta tags (timezone-normalized to UTC)
    │       ├── Extract article body text (regex block extraction,
    │       │   filter cookie/subscribe/sign-in noise, deduplicate blocks)
    │       └── Drop if body < 300 chars
    │
    ├── Filter + score:
    │   ├── Drop noise domains (google.com, gstatic.com)
    │   ├── Deduplicate by URL
    │   ├── _is_relevant(): require query token + cyber keyword hits
    │   ├── in_window(): post-filter by TimeWindow (if time_range given)
    │   └── _score_result():
    │       ├── +5 per query token in title
    │       ├── +2 per query token in body
    │       ├── +2 per cyber keyword in title
    │       ├── +1 per cyber keyword in body
    │       ├── +2 per trusted domain hint in host
    │       ├── +1 if published_at present
    │       └── -5 if URL path matches low-signal hints
    │           (/search/, /label/, /tag/, /category/, /anthology/, /archive/)
    │
    └── Return top max_articles by score
```

**TimeWindow** — proper interval parsing:
- `"2023"` → `[2023-01-01, 2024-01-01)` (not `[2023-01-01, ∞)`)
- `"last 2 years"` → `[now-730d, None)`
- `"last 6 months"` → `[now-180d, None)`
- Naive datetimes normalized to UTC before comparison

---

### 3.10 `app/agents/extraction.py` — ExtractionAgent

Two extraction paths run per article, LLM first with heuristic fallback.

```
ExtractionAgent.run(results)
    │
    ├── ThreadPoolExecutor (4 workers)
    │   └── Per article:
    │       ├── Try _extract_with_llm(result)
    │       │   ├── Build prompt with one-shot JSON example + explicit constraints:
    │       │   │   - affected_org must be VICTIM, not publisher/vendor/actor
    │       │   │   - software must be EXPLOITED/TARGETED, not just mentioned
    │       │   │   - IOCs must be actual indicators, not source domains
    │       │   ├── Call generate_json(system, user, model=extraction_model)
    │       │   └── Parse response into Incident or return None
    │       │
    │       └── If LLM returns None → _extract_heuristically(result)
    │           ├── CVE regex:    CVE-\d{4}-\d{4,7}
    │           ├── IOC extraction:
    │           │   ├── IP regex:  \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}
    │           │   ├── Domain regex: [a-zA-Z0-9.-]+\.(com|net|org|...)
    │           │   ├── Filter: noise domains (google, twitter, outlook, ...)
    │           │   ├── Filter: .gov, .edu
    │           │   └── Filter: source article's own hostname
    │           ├── Org regex: [A-Z]word+ (Inc|Corp|LLC|Ltd|Group|Hospital|Bank)
    │           │   └── Fallback: title prefix ending in org suffix
    │           ├── Malware: pattern list (Clop, LockBit, BlackCat, Akira, Conti, Ryuk)
    │           │   └── Title/snippet priority over body (avoid historical references)
    │           ├── Attack vector: substring match (sql injection, RCE, phishing, ...)
    │           ├── Software: headline-first extraction from KNOWN_SOFTWARE list
    │           │   ├── Search title+snippet first (high signal)
    │           │   ├── Body fallback only if headline empty
    │           │   └── Filter generic noise (VPN) from body-only results
    │           └── Date: body-first search (incident date), headline fallback,
    │                     published_at as last resort
```

---

### 3.11 `app/agents/postprocess.py` — PostProcessingAgent

Cleans and validates extraction output. Runs after ExtractionAgent, before enrichment.

```
PostProcessingAgent.run(incidents, query)
    │
    ├── For each incident:
    │   ├── _normalize_incident():
    │   │   ├── Strip site suffixes: "Big breach - SecurityWeek" → "Big breach"
    │   │   ├── Strip bad prefixes: "#StopRansomware:" → removed
    │   │   ├── _filter_cves():
    │   │   │   ├── Keep CVEs mentioned in title+summary
    │   │   │   ├── If none in title → keep at most 1 from body
    │   │   │   └── Prevents overview articles inflating CVE count
    │   │   ├── Normalize attack_vector: "zero-day" + CVEs → "vulnerability exploitation"
    │   │   └── _sanitize_org():
    │   │       ├── Drop if matches article title or incident name (copy-paste)
    │   │       ├── Drop if > 6 words (sentence fragment)
    │   │       ├── Drop if known vendor/publisher/analyst
    │   │       │   (Google Threat Intelligence, CrowdStrike, SentinelOne, ...)
    │   │       ├── Drop if contains: ransomware, threat, apt, hackers,
    │   │       │   cyber, discussion, advisory, intelligence
    │   │       └── Drop if contains garbage tokens: magenta, yellow, cyan,
    │   │           default, swatch, serif, bold, undefined, null, template
    │   │
    │   ├── _is_incident_relevant(incident, query_tokens):
    │   │   └── At least 1 query token must appear in name/summary/software/cves
    │   │
    │   └── _dedup_key(incident):
    │       └── Composite: primary_cve | malware | software | host | name
    │
    └── Return deduplicated, relevant, normalized incidents
```

---

### 3.12 `app/agents/enrichment.py` — CVEEnrichmentAgent

Queries NVD API for each unique CVE-ID across all incidents.

```
CVEEnrichmentAgent.run(incidents)
    │
    ├── Collect unique CVE-IDs (preserving order, deduplicating)
    │
    ├── For each CVE-ID:
    │   ├── Check nvd_cache → if hit, skip NVD call
    │   ├── Rate pacing: sleep(1.0s) between requests (NVD: 5 req/30s)
    │   ├── _fetch_cve(cve_id):
    │   │   ├── GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={id}
    │   │   ├── Parse CVSS: try v3.1 → v3.0 → v2 (first available)
    │   │   ├── Extract: description (English), severity, affected_products (CPE),
    │   │   │   references (URLs), cvss_score
    │   │   ├── On success: Vulnerability object + cache entry (24h TTL)
    │   │   └── On error: stub Vulnerability with only cve_id (NOT cached — avoids
    │   │       poisoning the cache for 24h on transient NVD failures)
    │   └── Log: cve_enriched or cve_enrichment_failed
    │
    └── Return list[Vulnerability]
```

---

### 3.13 `app/agents/report.py` — ReportAgent

Synthesizes narrative analysis from extracted incidents and vulnerabilities.

```
ReportAgent.run(query, incidents, vulnerabilities)
    │
    ├── Try _generate_with_llm():
    │   ├── Compact incidents + vulns to minimal JSON
    │   ├── Serialize via json.dumps (not Python repr) for clean LLM input
    │   ├── Prompt: "Create threat intelligence synthesis..."
    │   ├── Call generate_json(model=report_model)
    │   └── Returns: {executive_summary, key_findings, recommendations}
    │
    └── Fallback: _generate_heuristically():
        ├── Count malware families (Counter)
        ├── Count attack vectors (Counter)
        ├── Find highest CVSS score
        ├── Count critical vulnerabilities
        └── Template-generate executive_summary, key_findings, recommendations
```

---

### 3.14 `app/reporting.py` — Report builder

Pure function `build_report()` — assembles the final Report from all agent outputs.

```
build_report(query, incidents, vulnerabilities, source_count,
             executive_summary, key_findings, recommendations,
             telemetry, warnings)
    │
    ├── Hydrate incident-level CVE refs:
    │   └── For each incident, create IncidentCVERef from matching Vulnerability
    │       (maps cve_ids → related_vulnerabilities)
    │
    ├── Compute quality_metrics:
    │   └── incidents_with_dates, _organizations, _iocs, _cves
    │
    ├── Run evaluation harness:
    │   └── evaluate_report() → precision/recall/F1 if gold profile matches
    │
    ├── Build Markdown summary:
    │   ├── Header + stats
    │   ├── Executive Summary
    │   ├── Key Findings
    │   ├── Coverage Metrics
    │   ├── Per-incident details with enriched CVE refs
    │   ├── Recommendations
    │   └── Pipeline Telemetry (if present)
    │
    ├── Hydrate NodeTelemetry objects from dict entries
    │
    └── Return Report (all fields populated)
```

---

### 3.15 `app/evaluation.py` — Evaluation harness

Gold-query matching against `examples/eval_dataset.json`. Five profiles:
- moveit exploitation
- clop ransomware campaigns
- log4shell incidents
- fortinet vpn exploits
- solarwinds breach 2020

When query matches (normalized): computes cve_precision, cve_recall, cve_f1, malware_recall, software_recall, incident_count_score, field_coverage_score.

When no match: returns only field_coverage_score as a proxy quality metric.

---

### 3.16 `app/logging_utils.py` — Structured logging

Minimal: `configure_logging()` sets basicConfig, `log_event(logger, event, **fields)` emits JSON-serialized structured events with `ts` (ISO timestamp), `logger` (agent name), `event`, and all additional fields (including `run_id` where available). Every agent step, retry, failure, and completion is logged. LLM failures are logged with `provider`, `model`, `error` type, and first 200 chars of detail.

---

### 3.17 `ui/app.py` — Streamlit UI

Tabbed dashboard:
- **📋 Report** — executive summary, key findings, recommendations (each in bordered container)
- **🔍 Incidents** — per-incident cards with two-column layout, expandable CVE refs with descriptions, source summary expander
- **📊 Metrics** — evaluation metrics + coverage metrics in metric cards
- **⚙️ Pipeline** — per-node telemetry with timing, throughput, status, total pipeline time
- **{ } Raw JSON** — full report as formatted code block

Sidebar: configurable API base URL. Form: query + time_range + max_articles slider. Status polling with progress bar.

Reads `API_BASE_URL` from environment (defaults to localhost for local dev, overridden to `http://api:8000` in docker-compose for container-to-container communication).

---

### 3.18 Infrastructure files

**Dockerfile** — Python 3.12-slim, copies app/, examples/, tests/, ui/, pytest.ini. Entrypoint: uvicorn.

**docker-compose.yml** — Two services:
- `api` on port 8000 (uvicorn)
- `ui` on port 8501 (streamlit), depends_on api, `API_BASE_URL=http://api:8000`

**.dockerignore** — Excludes .git, .venv, __pycache__, .pytest_cache, .env to keep build context small.

**requirements.txt** — 9 dependencies: fastapi, uvicorn, pydantic, httpx, pytest, langgraph, anthropic, streamlit, python-dotenv.

**.env.example** — All configurable variables with comments.

**pytest.ini** — Sets pythonpath to project root.

---

## 4. Test coverage

42 tests across 5 files. All run without network access or API keys.

### test_api.py (5 tests)
- Full search lifecycle: POST → poll → COMPLETED → GET report with related_vulnerabilities
- 404 for unknown run_id (status + report)
- 422 for invalid query (< 3 chars)
- Health endpoint

### test_extraction.py (12 tests)
- Heuristic: CVE regex, IP regex, domain regex, malware detection, attack vector
- IOC filtering: source domain excluded, known noise (outlook.com) excluded
- Malware priority: title/snippet over body
- Edge cases: no CVEs/malware, published_at date fallback
- LLM path: mock generate_json → Incident, unavailable → None
- Software: headline-first detection, body fallback, VPN kept in headline but filtered from body
- Date: body date preferred over headline date

### test_postprocess.py (12 tests)
- Title normalization: site suffix stripping
- Deduplication: same source → one incident
- Relevance: unrelated incidents filtered, works for multiple query types
- Attack vector: zero-day → vulnerability exploitation when CVEs present
- Org sanitization: title match → None, known vendor → None, threat actor name → None, CSS garbage → None, real victim → kept
- Empty input → empty output

### test_enrichment.py (4 tests)
- Network error → stub Vulnerability fallback
- NVD response parsing: CVSS, severity, affected_products
- CVE deduplication: two incidents with same CVE → one fetch
- Cache: second run → zero NVD calls

### test_search.py (9 tests)
- TimeWindow: "last 2 years" → correct interval, "2023" → [Jan 1, Jan 1 next year)
- None/empty → None
- in_window: rejects out-of-range, accepts None datetime, normalizes naive datetime, normalizes non-UTC timezone
- Search: filters irrelevant results, returns empty on no results

---

## 5. Known limitations and trade-offs

| Area | Limitation | Mitigation | Production path |
|------|-----------|------------|----------------|
| Web discovery | Scraping is brittle | Dual-source + fault isolation + relevance scoring | Premium search/news API |
| Article parsing | Regex-based, misses JS-rendered content | Body length threshold + block dedup | Headless browser / readability parser |
| Org extraction | Low recall without NER | Heuristic regex + LLM + sanitization | spaCy NER as middle tier |
| Software detection | Substring matching produces noise | Headline-first + generic noise filter | Semantic similarity + CVE proximity |
| In-memory store | Not durable, not multi-worker | Async interface for easy swap | Redis/Postgres |
| In-memory cache | Same limitations | Thread-safe, TTL-based | Redis |
| NVD rate limits | 1s delay between requests | Cache (24h TTL) | NVD API key |
| Date extraction | Only ISO format regex | Body-first priority + published_at fallback | Multi-format date parser |
| Dedup | Source-centric (1 article = 1 incident) | Composite dedup key | Semantic clustering |
