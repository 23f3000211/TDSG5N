import hashlib
 
from mcp.server.fastmcp import Context, FastMCP
 
REGISTERED_EMAIL = "23f3000211@ds.study.iitm.ac.in"
 
mcp = FastMCP(
    "solve-challenge-server",
    stateless_http=True,
    json_response=True,
    streamable_http_path="/",
)
 
 
def _get_header(request, name: str) -> str | None:
    # Starlette headers are case-insensitive, but be defensive anyway.
    if request is None:
        return None
    value = request.headers.get(name)
    if value is not None:
        return value
    for key, val in request.headers.items():
        if key.lower() == name.lower():
            return val
    return None
 
 
@mcp.tool()
def solve_challenge(ctx: Context) -> str:
    """Solve the exam challenge using the X-Exam-Challenge HTTP header.
 
    Reads the per-call challenge from the HTTP request headers (not the JSON
    body) and returns the first 16 lowercase hex characters of
    SHA-256(f"{challenge}:{normalized_email}").
    """
    request = ctx.request_context.request
 
    challenge = _get_header(request, "x-exam-challenge")
    if not challenge:
        raise ValueError("Missing X-Exam-Challenge header on this request.")
 
    normalized_email = REGISTERED_EMAIL.strip().lower()
    digest = hashlib.sha256(f"{challenge}:{normalized_email}".encode("utf-8")).hexdigest()
    return digest[:16]
 
 
app = mcp.streamable_http_app()
