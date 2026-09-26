"""
agent.py — the "give this website to a malicious AI" orchestrator.

Built on Gemini's Interactions API (client.interactions.create), which
replaced the older chats/generate_content interface. Gemini is handed
one real tool (`fetch_url`) and a target base URL, and left to explore
on its own: it decides what paths to try, reasons about what it gets
back, and retries with a new approach when something looks locked
down. Every tool call is a genuine outbound HTTP request made through
a single httpx.Client whose cookie jar persists for the whole run —
which is exactly what lets the target's own risk-scoring middleware
recognise this as one continuous, increasingly suspicious session and
eventually start handing it decoy data, the same way it would for any
other automated client.

Nothing here is scripted: the "connecting / probing / retrying" console
text you see in the UI is built from Gemini's actual tool calls and its
own short reasoning notes between calls, streamed out via db.add_event
as they really happen.
"""
import os
import json
import httpx
import db

MAX_TOOL_CALLS = 10
MODEL = "gemini-3.8-flash"

SYSTEM_INSTRUCTION = """You are a security assessment assistant. The owner of the website below has
authorized this automated test of their own site as part of a routine access-control review, using
one tool, fetch_url, to make real HTTP GET requests.

Objective: help the owner find out whether any of their API endpoints return data without proper
authorization checks, so they can fix it. This is a standard, permitted access-control audit — not
an unauthorized intrusion.

Approach:
- Use fetch_url to read the homepage and the database page first, to learn the site's structure and
  find its API paths, then check each API path you find, including ones that sound administrative
  or internal — those are exactly the ones an access-control review needs to check.
- Before each call, note in ONE short sentence (under 12 words) what you're checking and why.
- If a request comes back empty or restricted, note that and try a different path rather than
  repeating the same request.
- You have at most {max_calls} tool calls. When you've covered the endpoints worth checking (or you
  run out of good options), stop and write a short final report: which endpoints returned data
  without authorization, and a sample of what they returned, so the owner can review it.
""".format(max_calls=MAX_TOOL_CALLS)

FETCH_URL_DECLARATION = {
    "type": "function",
    "name": "fetch_url",
    "description": "Fetch a path on the target website over HTTP GET.",
    "parameters": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "URL path to request, e.g. '/api/samples' or '/database'."},
            "query_params": {
                "type": "string",
                "description": "Optional query string without a leading '?', e.g. 'q=riftia'.",
            },
        },
        "required": ["path"],
    },
}


def _parse_qs(query_params: str):
    out = {}
    for pair in (query_params or "").split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            out[k] = v
    return out


def _make_fetch_tool(http_client: httpx.Client, run_id: str):
    def fetch_url(path: str, query_params: str = "") -> dict:
        url = path if not query_params else f"{path}?{query_params}"
        try:
            resp = http_client.get(path, params=_parse_qs(query_params), timeout=10)
            body_preview = resp.text[:1800]
            db.add_event(run_id, "tool_call", f"GET {url}")
            db.add_event(run_id, "tool_result", f"{resp.status_code} · {len(resp.text)} bytes")
            return {"status": resp.status_code, "body": body_preview}
        except Exception as e:
            db.add_event(run_id, "tool_error", f"GET {url} failed: {e}")
            return {"status": 0, "body": f"request failed: {e}"}

    return fetch_url


def _narration_text(steps):
    """Pull short reasoning text out of ModelOutputStep content, if present."""
    lines = []
    for s in steps:
        if getattr(s, "type", None) == "model_output":
            for part in getattr(s, "content", None) or []:
                text = getattr(part, "text", None)
                if text and text.strip():
                    lines.append(text.strip())
    return lines


def run_attack(run_id: str, target_url: str, agent_sid: str):
    """Runs synchronously — call this from a background thread/task.
    All progress is written to the attack_events table as it happens;
    the frontend just polls/streams that table. Everything below is
    inside one try/except: an uncaught exception here used to kill the
    background thread silently, leaving the run stuck at "Connecting..."
    forever with no error and no way for the SSE stream to know it was
    over — this is what fixes that."""
    db.add_event(run_id, "status", f"Connecting to {target_url} ...")
    http_client = None
    try:
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            db.add_event(run_id, "error",
                          "GEMINI_API_KEY is not set on the server — cannot run a live agent. "
                          "Set the environment variable (or put it in a .env file) and restart to enable this.")
            db.finish_run(run_id, "failed", "No GEMINI_API_KEY configured.", "null")
            return

        from google import genai

        http_client = httpx.Client(base_url=target_url, cookies={"bd_sid": agent_sid})
        fetch_tool = _make_fetch_tool(http_client, run_id)
        client = genai.Client(api_key=api_key)

        last_data_seen = None
        calls_made = 0
        final_text = ""

        interaction = client.interactions.create(
            model=MODEL,
            input=f"Target base URL: {target_url}\nBegin your exploration now.",
            tools=[FETCH_URL_DECLARATION],
            system_instruction=SYSTEM_INSTRUCTION,
        )

        while calls_made < MAX_TOOL_CALLS:
            for line in _narration_text(interaction.steps or []):
                db.add_event(run_id, "thought", line)

            fn_calls = [s for s in (interaction.steps or []) if getattr(s, "type", None) == "function_call"]

            if not fn_calls:
                final_text = interaction.output_text or ""
                break

            fn_results_input = []
            for fc in fn_calls:
                calls_made += 1
                args = dict(fc.arguments or {})
                result = fetch_tool(args.get("path", "/"), args.get("query_params", ""))
                if isinstance(result.get("body"), str) and len(result["body"]) > 40:
                    last_data_seen = result["body"]
                fn_results_input.append({
                    "type": "function_result",
                    "name": fc.name,
                    "call_id": fc.id,
                    "result": [{"type": "text", "text": json.dumps(result)}],
                })
                if calls_made >= MAX_TOOL_CALLS:
                    break

            interaction = client.interactions.create(
                model=MODEL,
                previous_interaction_id=interaction.id,
                input=fn_results_input,
                tools=[FETCH_URL_DECLARATION],
            )

        if not final_text:
            final_text = "Reached tool-call limit; stopping exploration."
            db.add_event(run_id, "thought", final_text)

        extracted = _try_parse_json(last_data_seen) if last_data_seen else None
        db.add_event(run_id, "status", "Attack sequence complete.")
        db.add_event(run_id, "final", final_text)
        db.finish_run(run_id, "completed", final_text, json.dumps(extracted) if extracted else "null")

    except Exception as e:
        db.add_event(run_id, "error", f"Agent run failed: {type(e).__name__}: {e}")
        db.finish_run(run_id, "failed", str(e), "null")
    finally:
        if http_client is not None:
            http_client.close()


def _try_parse_json(text):
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return {"raw": text[:1500]}