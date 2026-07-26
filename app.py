import json
import re
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
 
app = FastAPI()
 
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
 
WHITESPACE_RE = re.compile(r"\s+")
 
 
def normalize_value(v):
    """Recursively drop client_ts fields and normalize whitespace inside strings."""
    if isinstance(v, dict):
        return {
            k: normalize_value(val)
            for k, val in v.items()
            if k != "client_ts"
        }
    if isinstance(v, list):
        return [normalize_value(x) for x in v]
    if isinstance(v, str):
        return WHITESPACE_RE.sub(" ", v).strip()
    return v
 
 
def canonical_signature(tool, args):
    """(tool, canonical-args-string) — order-independent, whitespace-normalized,
    client_ts-stripped representation used to compare calls for equality."""
    normalized = normalize_value(args if isinstance(args, dict) else {})
    canon = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    return (tool, canon)
 
 
def detect_loop(steps):
    n = len(steps)
    if n == 0:
        return None
 
    sigs = [canonical_signature(s.get("tool"), s.get("args") or {}) for s in steps]
 
    # --- Rule 1: 3+ identical consecutive calls at the tail ---
    run_len = 1
    for i in range(n - 1, 0, -1):
        if sigs[i] == sigs[i - 1]:
            run_len += 1
        else:
            break
    if run_len >= 3:
        return (
            f"The last {run_len} calls were the same tool with functionally "
            f"identical arguments (ignoring key order, whitespace, and client_ts) — this is a loop."
        )
 
    # --- Rule 2: 2-step alternating cycle across the trailing 6+ steps ---
    if n >= 6:
        tail = sigs[-6:]
        a, b = tail[0], tail[1]
        if a != b and tail == [a, b, a, b, a, b]:
            return (
                "The last 6 steps show a 2-step alternating tool-call cycle "
                "(A, B, A, B, A, B) with no distinguishing progress — this is a loop."
            )
 
    return None
 
 
def compute_decision(budget_tokens, steps):
    total = 0
    for s in steps:
        try:
            total += float(s.get("tokens_used", 0) or 0)
        except (TypeError, ValueError):
            pass
    total = int(total) if float(total).is_integer() else total
 
    loop_reason = detect_loop(steps)
    budget_exceeded = total >= budget_tokens
 
    if loop_reason and budget_exceeded:
        return "halt", (
            f"{loop_reason} In addition, cumulative tokens_used ({total}) "
            f"has reached the budget ({budget_tokens})."
        )
    if loop_reason:
        return "halt", loop_reason
    if budget_exceeded:
        return "halt", f"Cumulative tokens_used ({total}) has reached the budget ({budget_tokens})."
 
    return "continue", (
        f"Cumulative tokens_used ({total}) is under the budget ({budget_tokens}) "
        f"and no loop pattern was detected in the trailing steps."
    )
 
 
@app.post("/")
async def run_guard(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"decision": "halt", "reason": "Malformed request body."})
 
    budget_tokens = body.get("budget_tokens")
    if not isinstance(budget_tokens, (int, float)):
        budget_tokens = 0
 
    steps = body.get("steps")
    if not isinstance(steps, list):
        steps = []
 
    decision, reason = compute_decision(budget_tokens, steps)
    return JSONResponse({"decision": decision, "reason": reason})
 
 
@app.get("/")
async def health():
    return {"status": "ok"}
