# TaskFlow API

A small task management REST API, used as an intentionally vulnerable sample application for demoing [Sentinel AI](https://github.com/[your-org]/sentinel-ai).

⚠️ **This repository contains deliberately planted security vulnerabilities.** Do not deploy this code or use it as a reference for production practices. See `VULNERABILITIES.md` for the full list.

## Running locally

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Endpoints

- `GET /tasks` — list tasks
- `POST /tasks` — create a task
- `DELETE /tasks` — clear all tasks (admin only)
- `GET /health` — health check
