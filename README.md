# LinkShield AI

Investigate Before You Trust. LinkShield AI combines a React dashboard, a shared FastAPI scanning service, and a Chrome MV3 companion. Website retrieval is server-side, bounded, and never executes target code. Risk scores come from deterministic scanner evidence; the optional Cerebras integration only explains that evidence.

## Local setup (Windows)

1. `cd backend; py -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -r requirements.txt; Copy-Item .env.example .env`
2. Apply the initial database migration: `alembic upgrade head`.
3. Start backend: `uvicorn app.main:app --reload` (health: http://127.0.0.1:8000/health, API docs: http://127.0.0.1:8000/docs).
4. `cd ..\frontend; npm install; npm run dev` and open the URL printed by Vite. Set `VITE_API_URL` to the backend origin if needed.
5. Chrome: open `chrome://extensions`, enable Developer mode, select **Load unpacked**, choose `chrome-extension`. Set the backend origin in the popup settings (defaults to localhost).

Configure `CEREBRAS_API_KEY` and `CEREBRAS_MODEL` in `backend/.env` for optional explanations. For optional URL reputation lookup, set `WEB_RISK_ENABLED=true` and `WEB_RISK_API_KEY`; this sends each full scanned URL to Google Web Risk. It is off by default. No key is required for static scanning. SQLite is created by the initial migration.

See [docs/SECURITY.md](docs/SECURITY.md), [docs/API.md](docs/API.md), and [docs/EXTENSION_SETUP.md](docs/EXTENSION_SETUP.md). This is a static remote-site inspection tool: it never executes target code, does not prove that a site is safe, does not run dynamic browser analysis, and cannot intercept every Chrome navigation or interaction. Reports show an evidence-weighted score and an INCONCLUSIVE verdict when analysis coverage is limited. An UNKNOWN result means evidence was insufficient.
