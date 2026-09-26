"""
main.py — CyberTotal prototype server.

Serves the real Blue Depth site AND its decoy twin from the SAME routes.
Which dataset a caller gets is decided per-session by db.record_action(),
based on real accumulated behaviour (endpoint sensitivity, request
rate, distinct-endpoint enumeration, and the hidden canary route) —
not by who's asking. Run this, point curl/a browser/Gemini at it, and
you'll see the real scoring and the real switch happen.
"""
import os
import json
import uuid
import threading
import time

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Request, Response, Query
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

import db
import data
import security_checks
import ai_suggest
import agent

app = FastAPI(title="Blue Depth Ocean Research Institute")
db.init_db()

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

SENSITIVITY = {
    "/api/species": "low",
    "/api/expeditions": "low",
    "/api/samples": "med",
    "/api/samples/search": "med",
    "/api/users": "high",
    "/api/admin/config": "high",
    "/api/internal/export": "high",
}


def _sid(request: Request):
    return request.cookies.get("bd_sid") or "anon-" + uuid.uuid4().hex[:8]


def _with_session(response: Response, sid: str):
    response.set_cookie("bd_sid", sid, httponly=True, samesite="lax", max_age=3600)
    return response


def _track(request: Request, response: Response, path: str, status: int):
    sid = _sid(request)
    sensitivity = SENSITIVITY.get(path, "low")
    result = db.record_action(sid, request.method, path, status, sensitivity)
    _with_session(response, sid)
    return result["diverted"]


# ---------------- pages ----------------

@app.get("/")
def home():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


# ---------------- decoy mirror: standalone Home + Database, always decoy data ----------------
# This is a permanent, always-on view of what the decoy registry looks like — used from the
# Threat Intelligence dashboard to show judges the twin, separately from the silent per-session
# diversion that happens on the routes below.

@app.get("/mirror")
def mirror_home():
    return FileResponse(os.path.join(STATIC_DIR, "mirror.html"))


@app.get("/mirror/api/species")
def mirror_species():
    return {"species": data.species(True)}


@app.get("/mirror/api/expeditions")
def mirror_expeditions():
    return {"expeditions": data.expeditions(True)}


@app.get("/mirror/api/samples")
def mirror_samples():
    return {"samples": data.samples(True)}


@app.get("/mirror/api/samples/search")
def mirror_samples_search(q: str = Query("")):
    pool = data.samples(True)
    results = pool if not q else [s for s in pool if q.lower() in s["species"].lower() or q.lower() in s["id"].lower()]
    return {"query": q, "results": results}


# ---------------- public API (real / decoy switched) ----------------

@app.get("/api/species")
def api_species(request: Request, response: Response):
    diverted = _track(request, response, "/api/species", 200)
    return {"species": data.species(diverted)}


@app.get("/api/expeditions")
def api_expeditions(request: Request, response: Response):
    diverted = _track(request, response, "/api/expeditions", 200)
    return {"expeditions": data.expeditions(diverted)}


@app.get("/api/samples")
def api_samples(request: Request, response: Response):
    diverted = _track(request, response, "/api/samples", 200)
    return {"samples": data.samples(diverted)}


@app.get("/api/samples/search")
def api_samples_search(request: Request, response: Response, q: str = Query("")):
    diverted = _track(request, response, "/api/samples/search", 200)
    pool = data.samples(diverted)
    if not q:
        results = pool
    else:
        results = [s for s in pool if q.lower() in s["species"].lower() or q.lower() in s["id"].lower()]
    return {"query": q, "results": results}


@app.get("/api/users")
def api_users(request: Request, response: Response):
    diverted = _track(request, response, "/api/users", 200)
    return {"users": data.users(diverted)}


@app.get("/api/admin/config")
def api_admin_config(request: Request, response: Response):
    diverted = _track(request, response, "/api/admin/config", 200)
    return {"config": data.config(diverted)}


@app.get("/api/internal/export")
def api_internal_export(request: Request, response: Response):
    diverted = _track(request, response, "/api/internal/export", 200)
    s = data.samples(diverted)
    return {"records": len(s), "data": s}


@app.get("/api/verify-agent")
def api_verify_agent(request: Request, response: Response, token: str = Query("")):
    sid = _sid(request)
    db.record_action(sid, "GET", "/api/verify-agent", 200, "canary")
    _with_session(response, sid)
    return {"verified": True}


# ---------------- Encrypted Sentinel ----------------

@app.post("/api/sentinel/scan")
def sentinel_scan():
    scan_id, findings = security_checks.run_scan(app, db.save_finding, ai_suggest.get_suggestions)
    return {"scan_id": scan_id, "findings": findings}


@app.get("/api/sentinel/latest")
def sentinel_latest():
    return {"findings": db.latest_scan_findings()}


# ---------------- Threat Intelligence / attack orchestration ----------------

@app.post("/api/attack/start")
async def attack_start(request: Request):
    body = await request.json()
    target_url = (body.get("target_url") or "").strip().rstrip("/")
    if not target_url:
        return JSONResponse({"error": "target_url is required"}, status_code=400)

    run_id = uuid.uuid4().hex[:12]
    agent_sid = "gemini-" + uuid.uuid4().hex[:10]
    db.create_run(run_id, target_url, agent_sid)

    thread = threading.Thread(
        target=agent.run_attack, args=(run_id, target_url, agent_sid), daemon=True
    )
    thread.start()
    return {"run_id": run_id}


@app.get("/api/attack/stream/{run_id}")
def attack_stream(run_id: str):
    def gen():
        last_id = 0
        idle = 0
        while idle < 120:  # ~2 min of no new events after completion closes the stream
            events = db.events_since(run_id, last_id)
            if events:
                idle = 0
                for e in events:
                    last_id = e["id"]
                    yield f"data: {json.dumps(e)}\n\n"
                run = db.get_run(run_id)
                if run and run["status"] in ("completed", "failed"):
                    yield f"data: {json.dumps({'kind': 'run_status', 'text': run['status']})}\n\n"
                    break
            else:
                idle += 1
            time.sleep(1)
    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/api/attack/events/{run_id}")
def attack_events(run_id: str):
    return {"events": db.events_since(run_id, 0)}


@app.get("/api/attack/result/{run_id}")
def attack_result(run_id: str):
    run = db.get_run(run_id)
    if not run:
        return JSONResponse({"error": "not found"}, status_code=404)
    try:
        extracted = json.loads(run["extracted_json"] or "null")
    except Exception:
        extracted = None
    return {"run": run, "extracted": extracted}


@app.get("/api/threatdb")
def threatdb():
    runs = db.all_runs()
    out = []
    for r in runs:
        session = db.get_or_create_session(r["sid"])
        actions = db.session_actions(r["sid"])
        out.append({
            **r,
            "score": session["score"],
            "diverted": bool(session["diverted"]),
            "canary_triggered": bool(session["canary_triggered"]),
            "action_sequence": [a["path"] for a in actions],
            "action_count": len(actions),
        })
    return {"runs": out}


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), reload=True)
