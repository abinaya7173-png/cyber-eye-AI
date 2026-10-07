# CYBER EYE AI

AI-powered real-time cybersecurity monitoring and threat detection platform.

## Architecture

External Laptop -> HTTPS -> FastAPI -> PostgreSQL -> AI Analysis -> Live Dashboard

## Stack

- Frontend: HTML/CSS/JavaScript dashboard served by FastAPI
- Backend: FastAPI
- Database: Supabase PostgreSQL
- AI: OpenAI Responses API (with safe rule-based fallback)
- External device: Python security agent
- Deployment: Docker + Render

## 1. Supabase

Create a Supabase project. Open SQL Editor and run `database/schema.sql`.

Copy the Postgres connection string from Supabase Connect.

## 2. Render

Create a Web Service from this GitHub repository.

Recommended settings:
- Environment: Docker
- Health check path: `/health`

Add environment variables:
- DATABASE_URL = Supabase connection string
- AGENT_API_KEY = a strong random secret
- OPENAI_API_KEY = your OpenAI API key
- AI_MODEL = gpt-5-mini

After deployment, open:
- `https://YOUR-SERVICE.onrender.com/`
- `https://YOUR-SERVICE.onrender.com/docs`

## 3. External laptop

On another laptop:

```bash
cd agent
pip install requests
```

Set the deployed API URL and agent key.

Windows PowerShell:
```powershell
$env:CYBER_EYE_API_URL="https://YOUR-SERVICE.onrender.com/api/events"
$env:CYBER_EYE_AGENT_KEY="YOUR_AGENT_API_KEY"
python agent.py
```

Linux/macOS:
```bash
export CYBER_EYE_API_URL="https://YOUR-SERVICE.onrender.com/api/events"
export CYBER_EYE_AGENT_KEY="YOUR_AGENT_API_KEY"
python agent.py
```

The agent sends a SAFE SIMULATED event. Do not use it against systems you do not own or have permission to test.

## Demo flow

1. Open the live dashboard on the evaluator's phone/laptop.
2. Open the agent on a second laptop.
3. Run `agent.py`.
4. The event travels over HTTPS to the cloud API.
5. FastAPI analyzes it.
6. The event is stored in PostgreSQL.
7. AI/rule engine classifies the event.
8. Dashboard refreshes and displays the threat.

## Security notes

- Never commit `.env`.
- Never put the OpenAI key in frontend JavaScript.
- Change the default AGENT_API_KEY before deployment.
- For production, restrict CORS to your actual frontend domain and add authentication/rate limiting.

## API

GET `/health`
GET `/api/stats`
GET `/api/events/recent`
POST `/api/events` with header `X-Agent-Key`

Swagger documentation:
`/docs`
