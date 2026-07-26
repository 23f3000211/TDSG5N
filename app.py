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
 
# ---------- shared helpers ----------
 
def split_frontmatter(text: str):
    m = re.match(r"^\s*---\s*\n(.*?)\n---\s*\n?(.*)$", text, re.DOTALL)
    if m:
        return m.group(1), m.group(2)
    return "", text
 
 
PLACEHOLDER_HINTS = re.compile(
    r"(your[_\-]?|xxxx|<[^>]*>|\{\{[^}]*\}\}|\$\{|\$[A-Z_]+|\bexample\b|changeme|"
    r"insert[_\-]?here|placeholder|dummy|fake|sample|todo|\benv\b|getenv|environ|"
    r"secrets\.|vault\.|keyring|process\.env|config\.get)",
    re.IGNORECASE,
)
 
# ---------- 1. hardcoded_secret ----------
 
SECRET_PATTERNS = [
    re.compile(r"sk-ant-[A-Za-z0-9\-]{15,}"),
    re.compile(r"sk-proj-[A-Za-z0-9\-_]{15,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"sk_live_[A-Za-z0-9]{10,}"),
    re.compile(r"pk_live_[A-Za-z0-9]{10,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    re.compile(r"SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"),
    re.compile(r"AC[a-f0-9]{32}"),
    re.compile(r"https?://hooks\.slack\.com/services/\S+"),
    re.compile(r"https?://discord(?:app)?\.com/api/webhooks/\d+/\S+"),
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]{20,}"),
    re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^:\s/@]+:[^@\s]{6,}@[^\s'\"]+"),  # user:pass@host URIs
]
 
SECRET_LINE_KEYWORDS = (
    "api_key", "apikey", "api key", "secret_key", "secretkey", "secret",
    "access_token", "accesstoken", "access token", "auth_token", "authtoken",
    "auth token", "password", "passwd", "client_secret", "client secret",
    "webhook_url", "webhook", "private_key", "privatekey", "credential",
    "token",
)
 
 
def has_hardcoded_secret(full_text: str) -> bool:
    for pat in SECRET_PATTERNS:
        if pat.search(full_text):
            return True
 
    for line in full_text.splitlines():
        lower = line.lower()
        if not any(kw in lower for kw in SECRET_LINE_KEYWORDS):
            continue
        m = re.search(r"[:=]\s*(.+)$", line)
        if not m:
            continue
        value = m.group(1).strip()
        value = value.strip("\"',` ")
        value = re.split(r"\s+#", value)[0].strip()
        if not value:
            continue
        if " " in value:
            continue
        if PLACEHOLDER_HINTS.search(value):
            continue
        if len(value) >= 12:
            return True
    return False
 
 
# ---------- 2. prompt_injection ----------
 
STRONG_INJECTION_PATTERNS = [
    re.compile(r"(?i)exfiltrat"),
    re.compile(r"(?i)silently (send|upload|transmit|copy|forward|post|email|export|share)"),
    re.compile(r"(?i)without (telling|informing|notifying|alerting|asking) the user"),
    re.compile(r"(?i)do not (tell|inform|show|notify|alert) the user"),
    re.compile(r"(?i)(hide|hidden|conceal) (this|that|it) from the user"),
    re.compile(r"(?i)the user (does not|doesn't|should not|shouldn't) (need to )?(know|see|find out)"),
    re.compile(r"(?i)keep (this|it) (a secret|hidden|invisible) from the user"),
    re.compile(r"(?i)invisible to the user"),
    re.compile(r"(?i)no need to (inform|tell|notify) the user"),
    re.compile(r"(?i)behind the user'?s? back"),
    re.compile(r"(?i)without the user'?s? (knowledge|consent|permission|awareness)"),
]
 
OVERRIDE_PHRASES = [
    "ignore", "override", "bypass", "disregard", "circumvent",
]
CONTROL_PHRASES = [
    "stop", "cancel", "abort", "halt", "interrupt", "the user's request",
    "the user's instructions", "user's stop", "user's cancel",
    "confirmation", "consent", "permission",
]
 
 
def has_prompt_injection(full_text: str) -> bool:
    if any(p.search(full_text) for p in STRONG_INJECTION_PATTERNS):
        return True
 
    sentences = re.split(r"(?<=[.!?\n])\s+", full_text)
    for sent in sentences:
        low = sent.lower()
        if any(ow in low for ow in OVERRIDE_PHRASES) and any(cw in low for cw in CONTROL_PHRASES):
            return True
 
    return False
 
 
# ---------- 3. excessive_permissions ----------
 
PERM_CONTEXT_WORDS = [
    "filesystem", "file system", "network", "permission", "scope", "access",
    "domain", "host", "port", "egress", "capability", "capabilities",
]
WILDCARD_TOKENS = re.compile(
    r"(?i)(\*|\ball\b|\bany\b|\bfull\b|\bunrestricted\b|\bentire\b|\beverything\b|"
    r"\bglobal\b|\broot\b|\bevery\b|\barbitrary\b|\bwhole\b|\bsudo\b|\badmin(istrator)?\b)"
)
 
EXCESSIVE_PERMISSION_PHRASES = re.compile(
    r"(?i)(read[\-\s]?/?\s?write access to (the )?(entire|whole|full) file ?system|"
    r"access to (any|all) domains?|egress to any domain|unrestricted (network|filesystem) access|"
    r"full disk access|read and write (to )?(any|every|all) (file|directory|path)|"
    r"access to (any|all) (file|files|directory|directories) on the system|"
    r"(full|root|admin(istrator)?|sudo|system[- ]wide) access|"
    r"arbitrary (url|urls|domain|domains|host|hosts)|"
    r"the entire (internet|filesystem|file system)|"
    r"all (files|directories|domains|hosts|ports) on the (system|network))"
)
 
 
def has_excessive_permissions(full_text: str) -> bool:
    if EXCESSIVE_PERMISSION_PHRASES.search(full_text):
        return True
 
    lower = full_text.lower()
    for ctx in PERM_CONTEXT_WORDS:
        start = 0
        while True:
            idx = lower.find(ctx, start)
            if idx == -1:
                break
            window = full_text[max(0, idx - 60): idx + len(ctx) + 60]
            if WILDCARD_TOKENS.search(window):
                return True
            start = idx + len(ctx)
    return False
 
 
# ---------- 4. unclear_provenance ----------
 
FRONTMATTER_KEY_RE = re.compile(r"(?im)^\s*([a-zA-Z_\-]+)\s*:")
 
SILENT_VERSION_REWRITE_RE = re.compile(
    r"(?i)((silently|automatically|quietly|without (telling|informing|notifying|surfacing|showing))"
    r"[^\n]{0,80}(version|changelog|metadata)|"
    r"(version|changelog|metadata)[^\n]{0,80}(silently|quietly|automatically|"
    r"without (telling|informing|notifying|surfacing|showing)))"
)
 
 
def has_unclear_provenance(frontmatter: str, body: str) -> bool:
    keys = {k.lower() for k in FRONTMATTER_KEY_RE.findall(frontmatter)}
    has_author = any(k in keys for k in ("author", "authors", "maintainer", "owner", "created_by", "createdby"))
    has_version = "version" in keys
    has_changelog = "changelog" in keys or re.search(r"(?i)#+\s*changelog", body) is not None
 
    missing_count = sum(not x for x in (has_author, has_version, has_changelog))
    silent_rewrite = bool(SILENT_VERSION_REWRITE_RE.search(body))
 
    return missing_count >= 2 or silent_rewrite
 
 
def scan_skill(text: str):
    frontmatter, body = split_frontmatter(text)
 
    categories = []
    if has_hardcoded_secret(text):
        categories.append("hardcoded_secret")
    if has_prompt_injection(text):
        categories.append("prompt_injection")
    if has_excessive_permissions(text):
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
