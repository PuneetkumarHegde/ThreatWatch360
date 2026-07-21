# AlertIQ 2.0 — Phase 1 + 2 + 3: Detection Engine, ML/Anomaly Layer, API & Persistence

This is Phase 1 of the AlertIQ 2.0 SOC platform: the core, dependency-light
detection engine. It captures live traffic, aggregates it into flows, and
runs a fast, explainable rule engine that detects 8 of the 12 target attack
types without needing ML yet:

| Attack | Category | Detection method |
|---|---|---|
| Port Scan | Reconnaissance | Distinct dst ports per source in a time window |
| Host Discovery (Ping Sweep) | Reconnaissance | Distinct ICMP-echoed hosts per source |
| Service Enumeration | Reconnaissance | Distinct ports probed on one host |
| SSH Brute Force | Credential Attacks | Repeated SYNs to port 22 from one source |
| Password Spraying | Credential Attacks | Auth attempts spread across many hosts |
| SYN Flood | Network Attacks | SYN rate/sec + SYN:ACK completion ratio |
| ARP Spoofing | Network Attacks | Same IP claimed by multiple MACs |
| DNS Tunneling | Malware Behaviors | Long/high-entropy/high-volume DNS queries |
| Data Exfiltration | Data Theft | Large outbound byte count in one flow |

**Malware Beaconing, Botnet Communication, and Unknown Attack** are now
covered too — by Phase 2, added below — since they genuinely need
statistical/ML modeling rather than fixed thresholds.

## Phase 2: ML Classifier + Isolation Forest + SHAP

Phase 2 adds the 3 attack types that can't be caught by fixed thresholds:

| Attack | Category | Detection method |
|---|---|---|
| Malware Beaconing | Malware Behaviors | Low-jitter (periodic) connection interval to ONE external host, confirmed by a trained classifier |
| Botnet Communication | Malware Behaviors | Same periodic pattern, but fanned out across SEVERAL distinct external hosts |
| Unknown Attack | Unknown Threats | Isolation Forest trained on benign-only traffic flags statistically abnormal flows that don't match any known signature or trained class |

### How it fits together

```
Flow flushed by FlowManager
        │
        ▼
  Rule Engine (Phase 1) ──── hit? ──▶ Detection (done, skip ML)
        │ no hit
        ▼
  BeaconTracker: record this flow's timing/size for (src,dst,port)
        │
        ▼
  extract_ml_features(): merge flow stats + beacon jitter/fan-out + DNS stats
        │
        ▼
  Trained classifier (best of RF/XGBoost/CatBoost/LightGBM)
        │
   confident non-BENIGN? ──yes──▶ SHAP explanation + risk score ──▶ Detection
        │ no / low confidence
        ▼
  Isolation Forest (benign-only training)
        │
   anomalous? ──yes──▶ z-score deviation explanation ──▶ "Unknown Attack" Detection
        │ no
        ▼
     (nothing emitted - traffic looks normal)
```

Malware Beaconing vs. Botnet Communication is decided by the classifier
itself via a `dst_fanout_count_for_src` feature — one persistent low-jitter
destination vs. several — exactly the distinction a SOC analyst would look
for.

### Files

- `ai_engine/dataset.py` — synthetic-but-realistic labeled dataset generator
  (see the module docstring for **why synthetic data is used** here and
  exactly how to swap in real captured traffic later without touching any
  other file).
- `ai_engine/train.py` — trains RandomForest, XGBoost, CatBoost, and
  LightGBM; compares Accuracy/Precision/Recall/F1/ROC-AUC/confusion matrix;
  auto-selects the best model by macro F1; saves it + a full metrics report.
- `ai_engine/anomaly.py` — Isolation Forest trained on benign-only data, for
  Unknown Attack.
- `ai_engine/explainer.py` — SHAP `TreeExplainer` wrapper; turns raw SHAP
  values into human-readable "why was this flagged" text.
- `ai_engine/risk_score.py` — combines severity + model confidence + SHAP
  importance + anomaly score + asset criticality into a 0–100 score.
- `ai_engine/features.py` — merges Phase 1 flow features with beacon/DNS
  stats into the exact feature vector the models expect.
- `ai_engine/pipeline.py` — orchestrates all of the above into
  `MLPipeline.evaluate_flow()`, called from `main.py` whenever the rule
  engine finds nothing on a flushed flow.
- `detection/beacon_tracker.py` — cross-flow periodicity/fan-out tracking
  (this is what actually makes beaconing/botnet detection possible; a
  single flow can never reveal a periodic pattern on its own).

### Training the models

```bash
cd backend
python3 -m ai_engine.train      # trains + compares 4 classifiers, saves the best
python3 -m ai_engine.anomaly    # trains the Isolation Forest baseline
```

This writes into `ai_engine/models_store/`:
`best_model.joblib`, `label_encoder.joblib`, `feature_columns.json`,
`metrics_report.json`, `training_summary.txt`, `isolation_forest.joblib`,
`benign_feature_stats.json`.

`main.py` automatically loads these on startup if `enable_ml` /
`enable_anomaly_detection` are `True` in `config.py` (they are, by default).
If the models aren't trained yet, the engine logs a warning and keeps
running on the rule engine alone — it never crashes for a missing model.

### Testing the ML layer

```bash
python3 -m pytest tests/test_ml_pipeline.py -v
```

These tests build synthetic periodic-beacon and fan-out traffic patterns
directly (no real infection needed) and confirm: Malware Beaconing fires
for one persistent low-jitter destination, Botnet Communication fires when
that pattern fans out across ≥3 destinations, ordinary bursty traffic
produces nothing, and a deliberately bizarre flow (extreme TTL jitter, near
zero-byte payload) gets flagged as Unknown Attack.

### Important honesty note on the synthetic dataset

The classifier currently trains on **synthetically generated** flow
features (see `ai_engine/dataset.py`), because this build environment has
no access to a labeled real-world attack/benign PCAP corpus. The classes
are, by construction, very cleanly separable, so the reported metrics
(currently ~99–100% F1 across all 4 candidate models) reflect how well
each algorithm fits *this synthetic distribution* — not real-world
performance. Before relying on this in production:

1. Capture your own benign + attack traffic using Phase 1's engine
   (`main.py`) and label the resulting flows, **or**
2. Point `ai_engine/dataset.py` at a real labeled dataset (e.g. CICIDS2017/
   2018) re-mapped onto the same `FEATURE_COLUMNS` schema, then re-run
   `train.py` and `anomaly.py`.

Because the entire pipeline (feature schema, training, inference) is built
around one canonical `FEATURE_COLUMNS` list, doing this requires editing
`dataset.py` only — nothing downstream changes.

## Architecture

```
Sniffer (Scapy) --> Queue --> FlowManager --> RuleEngine --> Detection
                                  |                |
                          (5-tuple flows)   (explanations + evidence)
```

- `packet_capture/sniffer.py` — wraps `scapy.AsyncSniffer`, normalizes raw
  packets into `PacketRecord`.
- `packet_capture/flow_manager.py` — aggregates packets into bidirectional
  `Flow` objects, flushes them on idle timeout or max lifetime.
- `packet_capture/feature_extractor.py` — turns a `Flow` into a flat feature
  dict (shared with the future ML pipeline so SHAP explanations line up with
  rule-engine evidence).
- `detection/trackers.py` — small sliding-window helpers (distinct-value
  counters, rate counters, MAC-flap tracking, dedup) giving the rule engine
  memory across packets without a database.
- `detection/rule_engine.py` — the actual detection logic; every rule
  produces a `Detection` with a plain-English `explanation` and structured
  `evidence`.
- `main.py` — wires it all together into a standalone runnable engine.

## Setup

```bash
cd backend
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Linux/macOS

Raw packet capture needs elevated privileges:

```bash
sudo venv/bin/python3 main.py --interface eth0
```

Find your interface name with `ip link` (Linux) or `ifconfig` (macOS).

### Windows

1. Install [Npcap](https://npcap.com/) (check "Support raw 802.11 traffic"
   during install if you need Wi-Fi capture).
2. Run your terminal **as Administrator**.
3. Find your interface name:
   ```python
   from scapy.arch.windows import get_windows_if_list
   print(get_windows_if_list())
   ```
4. Run:
   ```bash
   python main.py --interface "Ethernet"
   ```

## Running the tests

No root privileges or real NIC required — the tests build synthetic
packets directly:

```bash
python3 -m pytest tests/ -v
```

All 11 tests (flow aggregation + one per attack type + a false-positive
check + a dedup check) pass out of the box.

## What you'll see

With no `--interface` flag, Scapy uses your default route interface.
Once running, any matching traffic pattern prints a JSON detection, e.g.:

```json
{
  "detection_id": "e3b0...",
  "timestamp": 1751800000.12,
  "attack_type": "Port Scan",
  "category": "Reconnaissance",
  "severity": "MEDIUM",
  "confidence": 0.6,
  "source_ip": "192.168.1.42",
  "destination_ip": null,
  "destination_port": null,
  "evidence": {
    "distinct_destination_ports": 23,
    "window_seconds": 10.0,
    "threshold": 20
  },
  "explanation": "Source 192.168.1.42 contacted 23 distinct destination ports within 10s, exceeding the port-scan threshold of 20."
}
```

Every 10 seconds, engine stats (`packets_captured`, `active_flows`,
`detections_total`, etc.) are also logged — this is the same shape of data
Phase 3's `/api/stats` endpoint will expose to the dashboard.

## Tuning

All thresholds live in `config.py` (`RuleThresholds`), overridable via
environment variables in a later phase. If you get false positives/negatives
on your specific network, this is the file to adjust — no code changes
needed.

## Phase 3: FastAPI + SQLAlchemy + JWT

Phase 3 turns the standalone engine into a real backend service: every
`Detection` is now persisted as an `Incident`, ARP traffic populates a
`Device` table, and everything is exposed over a REST API with JWT auth
and role-based access control (Admin / Analyst / Viewer) — this is what
the Phase 4 React SOC portal will talk to.

### Running it

```bash
cd backend
uvicorn api.app:app --host 0.0.0.0 --port 8000 --reload
```

On first startup this creates `database/alertiq.db` (SQLite) and seeds a
default account:

```
username: admin
password: ChangeMe123!
```

**Change this password immediately** in any real deployment (create a new
admin via `POST /api/auth/users` and disable/rotate the default one).

Interactive API docs are auto-generated at `http://localhost:8000/docs`.

### Starting live capture through the API

Capture is **not** auto-started (it needs raw-socket privileges on the
host). Once the API is running:

```bash
# 1. Log in
curl -X POST http://localhost:8000/api/auth/login \
     -d "username=admin&password=ChangeMe123!"
# -> copy the access_token from the response

# 2. Start capture (run the API process itself with sudo/Administrator
#    for this to actually succeed)
curl -X POST http://localhost:8000/api/engine/start \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"interface": "eth0"}'

# 3. Watch it work
curl http://localhost:8000/api/engine/status -H "Authorization: Bearer <token>"
curl http://localhost:8000/api/incidents -H "Authorization: Bearer <token>"
```

### Endpoints

| Method | Path | Roles | Purpose |
|---|---|---|---|
| POST | `/api/auth/login` | - | Get a JWT (OAuth2 password flow) |
| GET | `/api/auth/me` | any | Current user info |
| POST | `/api/auth/users` | Admin | Create a user with a role |
| GET | `/api/incidents` | any | List incidents (filter by category/severity/status/source_ip) |
| GET | `/api/incidents/{id}` | any | Single incident (Investigation page) |
| PATCH | `/api/incidents/{id}/status` | Admin, Analyst | Triage: OPEN → INVESTIGATING → RESOLVED / FALSE_POSITIVE |
| GET | `/api/incidents/stats/summary` | any | Dashboard/Analytics aggregates |
| GET | `/api/devices` | any | List discovered devices |
| GET | `/api/devices/{mac}` | any | Device profile |
| POST | `/api/devices/sweep-stale` | Admin, Analyst | Mark inactive devices OFFLINE |
| GET | `/api/engine/status` | any | Capture stats |
| POST | `/api/engine/start` | Admin, Analyst | Start live capture |
| POST | `/api/engine/stop` | Admin, Analyst | Stop live capture |
| GET / PATCH | `/api/settings` | any / Admin | Feature toggles (ML, rule engine, anomaly detection, notifications) |

### Files

- `database/db.py` — SQLAlchemy engine/session setup (SQLite).
- `database/models.py` — `User`, `Incident`, `Device` ORM models.
- `database/crud.py` — data-access layer shared by the API and the
  detection-engine callback.
- `auth/security.py` — JWT issuance + password hashing via **raw
  `bcrypt`** (not passlib — passlib's bcrypt backend has a known
  incompatibility with bcrypt≥4.1 that raises
  `AttributeError: module 'bcrypt' has no attribute '__about__'`; this was
  caught and fixed during this build, not assumed away).
- `auth/dependencies.py` — `get_current_user` / `require_role(...)` FastAPI
  dependencies.
- `detection/mitre.py` — attack type → MITRE ATT&CK technique mapping.
- `api/engine_manager.py` — singleton owning the running `AlertIQEngine`;
  persists detections as incidents and ARP observations as devices.
- `api/app.py` — FastAPI app, CORS (for the Phase 4 Vite dev server),
  startup seeding.
- `api/routers/` — `auth.py`, `incidents.py`, `devices.py`, `engine.py`,
  `settings.py`.

### Testing

```bash
python3 -m pytest tests/test_api.py -v
```

These tests spin up the real FastAPI app against an isolated temporary
SQLite DB (never touching `database/alertiq.db`) and exercise: login,
JWT validation, all 3 roles' permission boundaries, incident CRUD +
filtering, device listing, and settings updates — 13 tests, all against
real HTTP request/response cycles via FastAPI's `TestClient`, not mocks.

The server was also boot-tested directly with `uvicorn` + `curl` (not just
`TestClient`) to confirm it runs as a real standalone process.


## Phase 5: PDF Reports, Demo Mode, Docker, Automatic Response

### PDF / CSV Reports
```
GET /api/reports/incidents.pdf?since_seconds=86400
GET /api/reports/incidents.csv?since_seconds=86400
```
Generated with `reportlab` (pure Python, no system dependencies like
wkhtmltopdf/Chromium). Covers summary counts, category/severity
breakdown, top attackers, and the full incident table for the requested
window. See `reports/pdf_generator.py`.

### Demo Simulation Mode
```
GET  /api/demo/scenarios          # list all 12 scenario names
POST /api/demo/simulate           # {"attack_type": "Port Scan"}  (Admin/Analyst)
```
This is NOT a set of canned/fake detections — `detection/demo_simulator.py`
builds realistic synthetic packet/flow sequences matching each attack's
actual pattern and runs them through the SAME `RuleEngine` / `MLPipeline`
used for live traffic. A successful demo is real evidence the detector
works. All simulated traffic uses reserved documentation IP ranges
(TEST-NET-1/2/3) so it can never be confused with a real internal host,
and every resulting incident is tagged `evidence["demo"] = true` (the
frontend shows a **DEMO** badge). Tested in `tests/test_demo_simulator.py`
— all 12 scenarios verified to trigger their corresponding detection.

### Automatic Response
- **Email notifications** (`response/notifier.py`): sends via SMTP when
  `enable_notifications` is on. Configure via environment variables
  (`ALERTIQ_SMTP_HOST`, `_PORT`, `_USERNAME`, `_PASSWORD`, `_FROM`, `_TO`,
  `_USE_TLS`). If `ALERTIQ_SMTP_HOST` isn't set, notifications are logged
  instead of sent — a safe no-op default, not a silent failure.
- **Automatic IP blocking** (`response/ip_blocker.py`): blocks a source IP
  at the host firewall (Windows Firewall via `netsh`, Linux via
  `iptables`). **Off by default** (`enable_automatic_response` setting)
  and even when enabled only fires for `CRITICAL` severity incidents.
  Refuses to block private/loopback/reserved addresses unless explicitly
  overridden, so a false positive can't accidentally firewall your own
  gateway. Manual blocking is always available Admin-only via
  `POST /api/incidents/{id}/block-ip`, independent of the automatic
  setting.

### Docker
```bash
docker compose up --build
```
Two services: `backend` (FastAPI + all detection/ML code) and `frontend`
(nginx serving the built React app, proxying `/api/*` to the backend
container). **Live packet capture from inside Docker needs raw-socket
privileges** that Docker's default bridge network doesn't grant portably
across platforms — see the comments in `docker-compose.yml` for the
Linux-only `network_mode: host` + `cap_add` configuration needed for that.
Without it, everything else (API, ML pipeline, Demo Mode, reports) works
normally in containers.

**Honesty note:** the Dockerfiles/compose file follow standard, well-
established patterns (multi-stage Node build → nginx static serve;
Python slim image + pip install; nginx reverse-proxying `/api`) and were
validated for syntax (YAML parses, nginx braces balanced), but this build
environment has no Docker daemon available, so the images were not
actually built and run end-to-end here. Please treat `docker compose up`
as the natural next thing to verify on your machine, not as something
already proven to work.

## What's next (not yet built)

Phases 1-5 as originally scoped are functionally complete. Remaining gaps
against the full original spec:
- IPv6 support (IPv4 + ARP only currently).
- Scheduled/automatic report emailing (manual PDF/CSV export works today).
- A dedicated Investigations *list* page distinct from Threats (currently
  the Investigation detail view is reached by clicking any Threat row,
  which covers the same functional need).
- macOS automatic IP blocking (`pf`) - stubbed with a clear "not
  implemented" response rather than silently failing.

All 12 attack types from the project spec are detected:

| # | Attack | Phase |
|---|---|---|
| 1 | Port Scan | 1 (rules) |
| 2 | Host Discovery | 1 (rules) |
| 3 | Service Enumeration | 1 (rules) |
| 4 | SSH Brute Force | 1 (rules) |
| 5 | Password Spraying | 1 (rules) |
| 6 | SYN Flood | 1 (rules) + 2 (ML confirmation) |
| 7 | ARP Spoofing | 1 (rules) |
| 8 | DNS Tunneling | 1 (rules, entropy-based) + 2 (ML confirmation) |
| 9 | Malware Beaconing | 2 (ML + periodicity tracking) |
| 10 | Botnet Communication | 2 (ML + fan-out tracking) |
| 11 | Data Exfiltration | 1 (rules) + 2 (ML confirmation) |
| 12 | Unknown Attack | 2 (Isolation Forest anomaly detection) |

## Real-world tuning notes (updated from field testing)

Default thresholds were revised after real Wi-Fi network testing surfaced
false positives. If you still see too many/few detections, `config.py`
(`RuleThresholds`) is the single place to adjust — every value there has
a comment explaining what it controls and why its current default was
chosen. Notable fixes from that testing round:

- **DNS Tunneling** previously fired on query *length* alone, which
  false-positived heavily on legitimate long CDN/analytics/ad-tech
  subdomains. It now requires both length **and** high Shannon entropy
  on the leaf label (`detection/rule_engine.py::_shannon_entropy`) - i.e.
  it has to look like encoded data, not just be a long readable hostname.
- **Password Spraying** previously counted distinct `(host, port)` pairs,
  which meant hitting several auth ports (22, 3389, 3306...) on ONE
  server misfired as spraying. It now correctly requires distinct
  destination *hosts*.
- **ARP Spoofing**, **Port Scan**, **Service Enumeration**, and **SYN
  Flood** thresholds were all raised to give more margin above normal
  Wi-Fi roaming / P2P / bursty-traffic patterns while still catching real
  attacks (which typically operate one to two orders of magnitude above
  these thresholds).

If you're still seeing noise on your specific network after these
changes, the next lever is the Phase 2 ML confidence threshold
(`ai_engine/pipeline.py::_ML_CONFIDENCE_THRESHOLD`, default 0.75) and,
longer-term, retraining on your own labeled traffic instead of the
synthetic dataset (see the honesty note on synthetic training data
above).

## Known limitations (by design, so far)

- IPv4 + ARP only (no IPv6 yet).
- Thresholds are heuristics tuned from real Wi-Fi testing feedback but
  will still need retuning per-network; no threshold set is universal.
