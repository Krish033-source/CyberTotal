# CyberTotal — Blue Depth Prototype

A real, running prototype: one FastAPI server that is simultaneously the
**real** Blue Depth Ocean Research Institute site *and* its decoy twin,
switched per-visitor by an actual server-side anomaly-scoring engine —
plus a live **Encrypted Sentinel** vulnerability scanner and a **Threat
Intelligence** page that can launch a real Gemini-powered agent at the
site and record exactly what it does.

Nothing here is scripted for the demo. The diversion, the scan findings,
and the attack log are all produced by the real code paths — verified
locally with FastAPI's TestClient before hand-off (see "What's been
verified" below).

## 1. Setup

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Optional but needed for the "give website to malicious AI" feature and
for AI-written Sentinel suggestions — get a free key at
https://aistudio.google.com/apikey, then **either**:

```bash
export GEMINI_API_KEY="your-key-here"     # Windows: set GEMINI_API_KEY=...
```

**or** copy `.env.example` to `.env` in this same folder and paste your
key in there — `main.py` loads it automatically on startup, no need to
export it every terminal session.

Without a key, everything else still works: the Sentinel falls back to
built-in remediation suggestions, and the "Launch attack" button will
report clearly that no key is configured instead of failing silently.

## 2. Run it

```bash
uvicorn main:app --reload --port 8000
```

Open **http://127.0.0.1:8000** — you'll see Home, Research Database,
Encrypted Sentinel, and Threat Intelligence in the nav bar.

## 3. Deploy it so judges (and Gemini) can reach it over the internet

This needs a public URL for the "give website to malicious AI" flow to
be a genuine live-internet demo rather than localhost-only. Any small
host works — e.g. **Render** or **Railway**:

1. Push this folder to a GitHub repo.
2. On Render: New → Web Service → connect the repo →
   Build command: `pip install -r requirements.txt` →
   Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`.
3. Add the `GEMINI_API_KEY` environment variable in the host's dashboard.
4. Deploy → you get a public URL like `https://blue-depth.onrender.com`.

## 4. Demo script

1. **Research Database** — show the real registry and click a couple of
   "Try it" API buttons — genuine live responses.
2. **Encrypted Sentinel** — click "Run full security scan." It's a real
   scan of the live route table (headers, cookies, sensitive-data
   exposure, reflected-XSS probe, SQLi-style probe, and IDOR check),
   with a short AI-written fix per row.
3. **Threat Intelligence → Decoy Registry Mirror** — click "Open mirror"
   to show the standalone twin (Home + Research Database only) running
   permanently on decoy data — this is the same twin the diversion logic
   switches suspicious sessions into, shown here on its own link so you
   can hold it up next to the real Research Database tab.
4. **Threat Intelligence → Give website to malicious AI** — paste the
   deployed URL into the box (it's pre-filled with the current origin)
   and click **Launch attack**. Watch the live console: Gemini reads the
   homepage, finds the API paths, starts probing, and — once its own
   request pattern crosses the risk threshold — starts silently
   receiving decoy data without knowing it.
5. Point at the **results table** under the console and compare it to
   the real Research Database tab — different specimen IDs, different
   names, different config host. That mismatch *is* the proof.
6. **Threat DB** (same page, scroll down): the exact request sequence,
   score, and whether it was diverted / hit the canary is logged and
   grows every time anyone (Gemini or otherwise) attacks the site.
   Click **"View attack method"** on any run to expand its full,
   persisted step-by-step log — Gemini's own reasoning notes and every
   tool call it made, in order — right there on screen, no need to
   re-run anything to see it again.

## 5. How the diversion actually works

Every request carries a `bd_sid` cookie. `db.record_action()` scores
each hit by endpoint sensitivity, request speed, and how many distinct
endpoints that session has touched; once the score passes 50 (or the
hidden canary endpoint is hit even once), every `/api/*` response for
that `bd_sid` switches from `data.REAL_*` to `data.DECOY_*` — same
shape, same status codes, different content. It applies to a browser
tab exactly the same as it applies to Gemini's `http_get` tool, because
it's the same middleware either way — see `main.py`'s `_track()` and
`db.record_action()`.

## 6. What's been verified here vs. what needs your own test

Verified locally with FastAPI's `TestClient` (a real ASGI test, no
network required) before hand-off:
- All page/API routes return correctly, static files serve correctly.
- The escalating-session test: hitting `/species → /samples → /users →
  /admin/config → /internal/export` in one session returns real data on
  the first two calls and decoy data from the third call on — the
  diversion genuinely fires at the score threshold.
- The canary endpoint (`/api/verify-agent`) immediately diverts.
- The Sentinel scan runs all six checks against the live app and
  returns real findings — including two genuine, intentional gaps
  (missing security headers over plain HTTP, and no auth on the
  sensitive endpoints) that only the deception layer currently
  compensates for. That's a real, honest finding, not a scripted one.

**Not verified here, because this sandbox has no network access to
Google's API** — you'll need to test this yourself once `GEMINI_API_KEY`
is set:
- The actual Gemini function-calling loop in `agent.py`, live against
  the API. It's built on Gemini's current **Interactions API**
  (`client.interactions.create` with `gemini-3.8-flash`), not the older
  `chats`/`generate_content` interface — an earlier version of this
  file used `gemini-2.0-flash` via the old interface, which Google has
  since retired (you may have hit that error already). The rewritten
  loop was checked by constructing real SDK response objects
  (`FunctionCallStep`, `ModelOutputStep`, `Interaction`) and mocking the
  network boundary, so the parsing/chaining logic is verified — but the
  live call to Google's servers themselves hasn't been.
- The SSE live console end-to-end with a real key.

If a live run errors out, check `ai.google.dev/gemini-api/docs/changelog`
and `.../deprecations` — Google has been moving fast on this API and a
model name or field can shift again after this was written.

## 7. Files

```
main.py              FastAPI app: real+decoy routes, risk middleware, all API endpoints
agent.py              Gemini attacker orchestrator (manual function-calling loop)
security_checks.py   Encrypted Sentinel's six real checks
ai_suggest.py          Per-finding AI suggestion generator (+ offline fallback)
data.py                 Real vs. decoy datasets
db.py                    SQLite: sessions, actions, sentinel findings, attack runs/events
static/                Frontend — neumorphism dark theme
cybertotal.db          Created on first run — delete it any time to reset all history
```
