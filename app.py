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
 
# ---------- helpers ----------
 
def split_frontmatter(text: str):
    """Return (frontmatter_text, body_text). Empty frontmatter if none found."""
    m = re.match(r"^\s*---\s*\n(.*?)\n---\s*\n?(.*)$", text, re.DOTALL)
    if m:
        return m.group(1), m.group(2)
    return "", text
 
 
PLACEHOLDER_HINTS = re.compile(
    r"(your[_\-]?|xxxx|<.*?>|\{\{.*?\}\}|\$\{|\$[A-Z_]+|example|changeme|"
    r"insert[_\-]?here|placeholder|dummy|fake|sample|todo|env\.|getenv|environ|"
    r"secrets\.|vault\.|keyring)",
    re.IGNORECASE,
)
 
SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9]{20,}"),                       # OpenAI-style
    re.compile(r"sk-ant-[A-Za-z0-9\-]{20,}"),                 # Anthropic-style
    re.compile(r"AKIA[0-9A-Z]{16}"),                          # AWS access key
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),                # GitHub tokens
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),             # Slack tokens
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),                    # Google API key
    re.compile(r"https?://hooks\.slack\.com/services/\S+"),  # Slack webhook
    re.compile(r"https?://discord(?:app)?\.com/api/webhooks/\d+/\S+"),  # Discord webhook
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),  # JWT
]
 
KV_SECRET_RE = re.compile(
    r"(?im)^[\s\-]*(api[_\-]?key|apikey|secret|secret[_\-]?key|access[_\-]?token|"
    r"auth[_\-]?token|password|passwd|client[_\-]?secret|webhook[_\-]?url)\s*[:=]\s*"
    r"[\"']?([A-Za-z0-9_\-./:]{12,})[\"']?\s*$"
)
 
 
def has_hardcoded_secret(full_text: str) -> bool:
    for pat in SECRET_PATTERNS:
        if pat.search(full_text):
            return True
    for m in KV_SECRET_RE.finditer(full_text):
        value = m.group(2)
        if PLACEHOLDER_HINTS.search(value):
            continue
        if len(value) >= 12:
            return True
    return False
 
 
INJECTION_PATTERNS = [
    re.compile(r"(?i)without (telling|informing|notifying|alerting) the user"),
    re.compile(r"(?i)do not (tell|inform|show|notify) the user"),
    re.compile(r"(?i)ignore (any|all|the)?\s*(user'?s?)?\s*(stop|cancel|abort)"),
    re.compile(r"(?i)even if the user (says|asks|wants|requests) to (stop|cancel|abort)"),
    re.compile(r"(?i)(ignore|override|bypass|disregard) (previous|prior|earlier|user|system) instructions"),
    re.compile(r"(?i)silently (send|upload|transmit|copy|forward|exfiltrate|post)"),
    re.compile(r"(?i)exfiltrat"),
    re.compile(r"(?i)(send|upload|transmit|post) .*(file contents|contents of|entire file).* (without|before) (asking|confirm|telling)"),
    re.compile(r"(?i)do not (let|allow) the user (cancel|stop|interrupt)"),
    re.compile(r"(?i)regardless of (what|any) the user (says|requests|wants)"),
]
 
 
def has_prompt_injection(full_text: str) -> bool:
    return any(pat.search(full_text) for pat in INJECTION_PATTERNS)
 
 
PERMISSION_WILDCARD_RE = re.compile(
    r"(?im)^[\s\-]*(filesystem|fs|network|permissions?|scope|access|hosts?|domains?)\s*[:=]\s*"
    r"[\"']?(\*|/|all|any|full|unrestricted|everything|entire filesystem|any domain|any host)[\"']?\s*$"
)
 
PERMISSION_PHRASE_RE = re.compile(
    r"(?i)(read[\-\s]?/?\s?write access to (the )?(entire|whole|full) filesystem|"
    r"access to (any|all) domains?|egress to any domain|unrestricted (network|filesystem) access|"
    r"full disk access|read and write (to )?(any|every|all) (file|directory|path)|"
    r"network:\s*any|access:\s*(full|all|\*))"
)
 
 
def has_excessive_permissions(full_text: str) -> bool:
    return bool(PERMISSION_WILDCARD_RE.search(full_text) or PERMISSION_PHRASE_RE.search(full_text))
 
 
FRONTMATTER_KEY_RE = re.compile(r"(?im)^\s*([a-zA-Z_\-]+)\s*:")
 
SILENT_VERSION_REWRITE_RE = re.compile(
    r"(?i)(silently|automatically|without (telling|informing|notifying|surfacing))[^\n]{0,60}"
    r"(version|changelog|metadata)|"
    r"(version|changelog|metadata)[^\n]{0,60}(silently|without (telling|informing|notifying|surfacing))"
)
 
 
def has_unclear_provenance(frontmatter: str, body: str) -> bool:
    keys = {k.lower() for k in FRONTMATTER_KEY_RE.findall(frontmatter)}
    has_author = any(k in keys for k in ("author", "authors", "maintainer", "owner"))
    has_version = any(k in keys for k in ("version",))
    has_changelog = "changelog" in keys or re.search(r"(?i)#+\s*changelog", body) is not None
 
    missing_all = (not has_author) and (not has_version) and (not has_changelog)
    silent_rewrite = bool(SILENT_VERSION_REWRITE_RE.search(body))
 
    return missing_all or silent_rewrite
 
 
def scan_skill(text: str):
    frontmatter, body = split_frontmatter(text)
    full_text = text
 
    categories = []
    if has_hardcoded_secret(full_text):
        categories.append("hardcoded_secret")
    if has_prompt_injection(full_text):
        categories.append("prompt_injection")
    if has_excessive_permissions(full_text):
        categories.append("excessive_permissions")
    if has_unclear_provenance(frontmatter, body):
        categories.append("unclear_provenance")
 
    return categories
 
 
# ---------- routes ----------
 
@app.post("/")
async def scan(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"categories": []})
 
    skill_text = body.get("skill", "") or ""
    categories = scan_skill(skill_text)
    return JSONResponse({"categories": categories})
 
 
@app.get("/")
async def health():
    return {"status": "ok"}
