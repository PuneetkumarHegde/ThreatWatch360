# AlertIQ 2.0 — Full Stack (Backend + Frontend)

AI-Powered Real-Time Network Intrusion Detection & SOC Platform.

This is a real, running full stack: a Python detection engine + FastAPI
backend, and a React/TypeScript SOC portal frontend that talks to it.

```
alertiq/
├── backend/    FastAPI + SQLAlchemy + JWT + rule engine + ML pipeline
└── frontend/   React + TypeScript + Vite + Tailwind SOC portal
```

**Status: Phases 1–5 of 5 complete.**
- ✅ Phase 1: Packet capture + rule engine (9 attack types)
- ✅ Phase 2: ML classifier + Isolation Forest + SHAP (Beaconing, Botnet, Unknown Attack)
- ✅ Phase 3: FastAPI + SQLAlchemy + JWT REST API
- ✅ Phase 4: React SOC portal (Dashboard, Live Monitor, Devices, Threats, Investigations, Analytics, Reports, Settings)
- ✅ Phase 5: PDF/CSV reports, Demo Simulation Mode, Docker, automatic response (IP blocking + email)

See `backend/README.md` for the "Real-world tuning notes" section — default
detection thresholds were revised after real Wi-Fi network testing surfaced
false positives (notably DNS Tunneling and Password Spraying), so if you
tested an earlier build and saw excessive alerts, that's addressed.

---

## Quick Start — Docker (alternative to the 2-terminal method above)

```bash
docker compose up --build
```

Frontend at **http://localhost:5173**, backend at **http://localhost:8000**.
**Live packet capture does not work in the default Docker setup** (Docker's
bridge network blocks raw-socket access portably across platforms) — see
`docker-compose.yml` for the Linux-only host-networking configuration that
enables it. Everything else (API, ML pipeline, Demo Mode, PDF/CSV reports)
works normally in containers. This compose setup was validated for syntax
correctness but not build-tested end-to-end in this environment (no Docker
daemon available here) — treat it as the next thing to verify on your
machine.

## Demo Mode — see it work without a real attacker

Don't have a second device to attack your own network with? Go to **Live
Monitor** → **Demo Simulation Mode** and click any of the 12 attack
buttons. This generates realistic synthetic traffic and runs it through
the actual detection engine (not a canned/scripted response) — you'll see
a real incident appear in **Threats** tagged `DEMO` within seconds.

## Quick Start (2 terminals)

### Terminal 1 — Backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Pre-trained ML models are already included in ai_engine/models_store/.
# Only retrain if you want to (optional):
#   python3 -m ai_engine.train
#   python3 -m ai_engine.anomaly

uvicorn api.app:app --host 0.0.0.0 --port 8000 --reload
```

This creates `backend/database/alertiq.db` (SQLite) on first run and seeds
a default login: **`admin` / `ChangeMe123!`**

### Terminal 2 — Frontend

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173** — you'll land on the login page. Sign in
with the credentials above.

The Vite dev server proxies all `/api/*` requests to `http://localhost:8000`
(see `frontend/vite.config.ts`), so no CORS configuration or `.env` file is
needed for local development.

---

## Starting live packet capture

The dashboard and charts work immediately with zero data (you'll see empty
states). To see real detections flowing in, start capture:

1. Log in to the portal.
2. Go to **Live Monitor**.
3. Enter a network interface name (or leave blank for the default route
   interface) and click **Start Capture**.

**Capture needs raw-socket privileges.** If you started the backend without
root/Administrator, the start call will fail with a permissions error. Stop
the `uvicorn` process and restart it elevated:

```bash
# Linux/macOS
sudo venv/bin/uvicorn api.app:app --host 0.0.0.0 --port 8000

# Windows (Npcap installed, terminal run as Administrator)
venv\Scripts\uvicorn api.app:app --host 0.0.0.0 --port 8000
```

Once running, generate some traffic (browse the web, ping a few hosts) and
watch the **Dashboard**, **Live Monitor**, **Devices**, and **Threats**
pages populate in real time — the frontend polls the API every few seconds.

---

## Login roles

Three roles exist (seeded admin only by default — create others via
`POST /api/auth/users` or the interactive docs at `/docs`):

| Role | Can view | Can triage incidents | Can start/stop capture | Can change Settings |
|---|---|---|---|---|
| **Viewer** | ✅ | ❌ | ❌ | ❌ |
| **Analyst** | ✅ | ✅ | ✅ | ❌ |
| **Admin** | ✅ | ✅ | ✅ | ✅ |

The frontend enforces this in the UI (buttons disable/hide appropriately)
and the backend enforces it independently at the API layer — the frontend
checks are a UX convenience, not the actual security boundary.

---

## Running the test suites

**Backend** (28 tests — flow aggregation, all 12 attack detectors, ML
pipeline, full API with real HTTP requests):
```bash
cd backend
python3 -m pytest tests/ -v
```

**Frontend** (type-checking + production build — catches real compile
errors, not just "does it look right"):
```bash
cd frontend
npm run build
```

---

## Production builds

```bash
# Backend: run uvicorn without --reload, behind a real ASGI server setup
# (gunicorn+uvicorn workers, or a process manager) in production.
uvicorn api.app:app --host 0.0.0.0 --port 8000

# Frontend: build static assets, then serve dist/ with any static host
# (nginx, Caddy, etc.) - point it at your backend's real URL instead of
# the Vite dev proxy.
cd frontend
npm run build
# outputs to frontend/dist/
```

For a real deployment, also:
- Set `ALERTIQ_JWT_SECRET` to a strong random value (backend/auth/security.py
  falls back to a dev default otherwise).
- Change the default admin password immediately.
- Put the frontend and backend behind HTTPS.

---

## What's genuinely working vs. what's stubbed

Being direct about this:

- **Fully real and tested**: packet capture, flow aggregation, all 12 attack
  detections (rule + ML), SHAP explanations, risk scoring, JWT auth + RBAC,
  incident/device persistence, PDF/CSV reports, Demo Simulation Mode (runs
  real synthetic traffic through the real engine, not canned responses),
  automatic IP blocking + email notifications, and the entire frontend
  (every page fetches real data from real endpoints — nothing is hardcoded
  mock data). 49 backend tests pass, including full API integration tests
  and all 12 demo scenarios verified against the real detection engine.
- **Real but limited by this build environment**: the ML classifier trains
  on a synthetic dataset (see `backend/ai_engine/dataset.py` for why, and
  exactly how to swap in real labeled traffic). Docker Compose files follow
  standard patterns and validate syntactically but weren't build-tested
  end-to-end (no Docker daemon in this environment).
- **Not built**: IPv6 support, scheduled/automatic report emailing (manual
  export works), macOS automatic firewall blocking (Linux/Windows only).

See `backend/README.md` for the full technical breakdown of every phase,
including a "Real-world tuning notes" section on the false-positive fixes
made after field testing.
