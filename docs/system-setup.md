# APKShield-AI 🛡️

> GenAI-Assisted Hybrid Malware Analysis Platform for Fraudulent Android APK Detection in Banking Ecosystems

---

## Prerequisites

Make sure the following are installed on your machine before anything else.

| Tool | Version | Download |
|------|---------|----------|
| Docker Desktop | Latest | https://www.docker.com/products/docker-desktop |
| Python | 3.11+ | https://www.python.org/downloads |
| uv (Python package manager) | Latest | https://github.com/astral-sh/uv |
| Node.js | 18+ | https://nodejs.org |
| Git | Latest | https://git-scm.com |

---

## Project Structure

```
apkshield/
├── docker-compose.yml
├── .env                        ← you create this (never commit)
├── .gitignore
├── README.md
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── main.py
├── frontend/
│   ├── Dockerfile
│   └── src/
├── mobsf/                      ← auto-created by Docker
└── uploads/                    ← APKs land here
```

---

## Step 1 — Clone the Repository

```bash
git clone https://github.com/your-username/apkshield.git
cd apkshield
```

---

## Step 2 — Create the .env File

> ⚠️ Never commit this file. It holds your secret API keys.

On **Windows (PowerShell)**:

```powershell
"ANTHROPIC_API_KEY=your_anthropic_key_here" | Out-File -FilePath .env -Encoding utf8
"MOBSF_API_KEY=your_mobsf_key_here" | Add-Content -Path .env -Encoding utf8
```

On **Mac / Linux**:

```bash
echo "ANTHROPIC_API_KEY=your_anthropic_key_here" > .env
echo "MOBSF_API_KEY=your_mobsf_key_here" >> .env
```

Verify it looks correct (no quotes around values):

```bash
cat .env
```

Expected output:
```
ANTHROPIC_API_KEY=your_anthropic_key_here
MOBSF_API_KEY=your_mobsf_key_here
```

### Where to get the API keys

- **ANTHROPIC_API_KEY** — https://console.anthropic.com → API Keys
- **MOBSF_API_KEY** — found in the MobSF UI after it starts at `http://localhost:8008` → REST API docs page. Leave this as a placeholder for now and fill it in after first run.

---

## Step 3 — Install Python Dependencies (for local development)

```bash
cd backend
uv pip install -r requirements.txt
cd ..
```

---

## Step 4 — Start Docker Desktop

> Docker Desktop must be running before any Docker commands will work.

- **Windows / Mac** — Open Docker Desktop from your Start menu or Applications folder
- Wait for the whale icon in the taskbar to stop animating
- Confirm it is running:

```bash
docker --version
docker-compose --version
```

---

## Step 5 — Build and Start All Services

From the project root:

```bash
docker-compose up --build
```

First run will take 5–10 minutes — it downloads base images and installs tools (jadx, apktool, Java).

Subsequent starts are much faster:

```bash
docker-compose up
```

---

## Step 6 — Verify Everything is Running

Open these in your browser:

| Service | URL | What it is |
|---------|-----|------------|
| Frontend | http://localhost:3000 | React dashboard |
| Backend API | http://localhost:8000/docs | FastAPI auto-docs |
| MobSF | http://localhost:8008 | Static + dynamic analysis UI |

Test the backend is alive:

```bash
curl http://localhost:8000/api/health
```

Expected response:
```json
{ "status": "ok" }
```

---

## Common Docker Commands

### Start services
```bash
docker-compose up              # start (use existing build)
docker-compose up --build      # start and rebuild images
docker-compose up -d           # start in background (detached mode)
```

### Stop services
```bash
docker-compose down            # stop and remove containers
docker-compose down -v         # stop and also delete volumes (resets MobSF data)
```

### View logs
```bash
docker-compose logs                  # all services
docker-compose logs backend          # backend only
docker-compose logs -f backend       # backend, live follow
```

### Restart a single service
```bash
docker-compose restart backend
```

### Rebuild a single service
```bash
docker-compose up --build backend
```

### Open a shell inside a container
```bash
docker-compose exec backend bash
```

### Check running containers
```bash
docker ps
```

---

## Testing the Upload Endpoint

Once everything is running, test APK upload:

**Windows (PowerShell):**
```powershell
curl -X POST http://localhost:8000/api/upload -F "file=@C:\path\to\sample.apk"
```

**Mac / Linux:**
```bash
curl -X POST http://localhost:8000/api/upload -F "file=@/path/to/sample.apk"
```

Expected response:
```json
{
  "case_id": "a1b2c3d4",
  "filename": "sample.apk",
  "sha256": "e3b0c44298fc...",
  "size_bytes": 2048576,
  "status": "unpacked"
}
```

---

## Troubleshooting

### Docker daemon not running
```
unable to get image: failed to connect to the docker API
```
→ Open Docker Desktop and wait for it to fully start before retrying.

---

### .env values have quotes around them
```
"ANTHROPIC_API_KEY=sk-ant-..."   ← wrong
ANTHROPIC_API_KEY=sk-ant-...     ← correct
```
→ On Windows, use `Out-File` instead of `echo` to write the `.env` file (see Step 2).

---

### Port already in use
```
Bind for 0.0.0.0:8000 failed: port is already allocated
```
→ Either stop the process using that port, or change the port mapping in `docker-compose.yml`:
```yaml
ports:
  - "8001:8000"   ← change left side only
```

---

### version attribute warning
```
the attribute `version` is obsolete
```
→ Delete the `version: "3.9"` line from the top of `docker-compose.yml`. This is harmless but noisy.

---

### Container exits immediately
```bash
docker-compose logs backend    # check what error it printed
```

---

## .gitignore

Make sure your `.gitignore` contains at minimum:

```
.env
uploads/
mobsf/
__pycache__/
*.pyc
node_modules/
```

---

## Environment Variables Reference

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Yes | Claude API key for the GenAI interpretation layer |
| `MOBSF_API_KEY` | Yes | MobSF REST API key for programmatic analysis calls |

---

*APKShield-AI — Swara Deshpande, 2026*