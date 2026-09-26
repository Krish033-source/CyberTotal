"""
ai_suggest.py — turns the Encrypted Sentinel's raw findings table into
one short, actionable suggestion per row, using Gemini. Falls back to
a static rule-of-thumb suggestion if GEMINI_API_KEY isn't set or the
call fails, so the scanner still works out of the box.
"""
import os
import json

_FALLBACK = {
    "Security Misconfiguration: headers": "Add the missing security headers at the edge/middleware layer.",
    "Security Misconfiguration: cookies": "Reissue the cookie with HttpOnly, Secure and SameSite=Lax set.",
    "Sensitive Data Exposure": "Strip internal identifiers/secrets from the response payload before it ships.",
    "Reflected XSS indicator": "Keep this response as JSON only; never render it directly as HTML.",
    "SQL Injection indicator": "Keep using parameterised queries — no change needed.",
    "Broken Access Control / IDOR": "Require an authenticated, authorised session before returning this data.",
}


def _fallback_suggestion(row):
    if row["result"] == "PASS":
        return "No action needed."
    return _FALLBACK.get(row["check_type"], "Review this endpoint against OWASP ASVS guidance.")


def get_suggestions(findings):
    """findings: list of {endpoint, check_type, result, evidence}. Returns
    a list of one-line strings, same order/length as findings."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key or not findings:
        return [_fallback_suggestion(f) for f in findings]

    try:
        from google import genai
        client = genai.Client(api_key=api_key)
        table = [
            {"endpoint": f["endpoint"], "check": f["check_type"], "result": f["result"], "evidence": f["evidence"]}
            for f in findings
        ]
        prompt = (
            "You are a security reviewer. For each row of this findings table, write ONE short "
            "actionable remediation sentence (under 15 words). If result is PASS, reply exactly "
            "'No action needed.' for that row. Return ONLY a JSON array of strings, same length "
            "and order as the input, no markdown, no extra text.\n\n"
            f"{json.dumps(table)}"
        )
        resp = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
        )
        text = (resp.text or "").strip()
        if text.startswith("```"):
            text = text.strip("`")
            text = text.split("\n", 1)[1] if "\n" in text else text
        suggestions = json.loads(text)
        if isinstance(suggestions, list) and len(suggestions) == len(findings):
            return [str(s) for s in suggestions]
    except Exception:
        pass

    return [_fallback_suggestion(f) for f in findings]
