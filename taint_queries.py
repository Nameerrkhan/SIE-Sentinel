from __future__ import annotations

from dataclasses import dataclass

@dataclass
class TaintQuery:
    id: str
    cwe: str
    title: str
    query: str
    sources: str

SINK_QUERIES: list[TaintQuery] = [
    TaintQuery(
        "cmd-exec", "CWE-78",
        "OS command / process execution",
        "spawning a process or shell command: Command::new, subprocess, "
        "child_process.exec, os.system, ProcessBuilder, shell -c, exec, popen",
        "request body, config field, webhook payload, repo/branch name, filename",
    ),
    TaintQuery(
        "path-traversal", "CWE-22",
        "Path traversal / arbitrary file access",
        "building a filesystem path from input and reading or writing it: "
        "path join without canonicalize, open(user_path), fs::read, sendFile, "
        "directory listing from a query parameter",
        "path/filename query param, request-supplied working_dir, archive entry",
    ),
    TaintQuery(
        "sql-injection", "CWE-89",
        "SQL / NoSQL injection",
        "constructing a database query by string concatenation or interpolation "
        "with user input instead of parameterized queries",
        "request field, search term, id parameter",
    ),
    TaintQuery(
        "dom-xss", "CWE-79",
        "DOM / stored XSS sink",
        "writing untrusted data into the DOM: innerHTML, outerHTML, insertAdjacentHTML, "
        "document.write, dangerouslySetInnerHTML, jQuery .html(), eval, new Function",
        "scraped page HTML, network response, message payload, URL fragment",
    ),
    TaintQuery(
        "missing-authz", "CWE-306",
        "Missing authentication / authorization on a sensitive route",
        "an HTTP route or handler that performs a privileged action with no auth "
        "check, no session, no token, no permission guard; router or middleware setup",
        "any remote or cross-origin caller",
    ),
    TaintQuery(
        "origin-bypass", "CWE-346",
        "Weak origin / CORS / host validation",
        "cross-origin or websocket origin validation: CORS allow_origin, Origin "
        "header check, Host header check, postMessage listener without origin check, "
        "sender validation on a message handler",
        "malicious web page, DNS-rebinding, cross-site request",
    ),
    TaintQuery(
        "ssrf", "CWE-918",
        "Server-side / client-side request forgery",
        "fetching a URL taken from input without validating scheme or host; "
        "credentialed fetch of an attacker-supplied URL, relaying the response",
        "URL field in a request or page JSON",
    ),
    TaintQuery(
        "secret-exposure", "CWE-200",
        "Secret exposure in response, log, or config",
        "returning or logging credentials: API token, PAT, OAuth token, password "
        "serialized into an API response, printed to a log, or written world-readable",
        "any client that can reach the endpoint or read the log/file",
    ),
    TaintQuery(
        "weak-crypto-auth", "CWE-347",
        "Signature / HMAC verification weakness",
        "verifying an HMAC or signature on a webhook or token: comparison that is "
        "not constant-time, verification skipped when no secret is set, verify after "
        "acting on the body",
        "forged webhook, unsigned request",
    ),
    TaintQuery(
        "priv-drop", "CWE-271",
        "Incomplete privilege drop",
        "dropping privileges after running as root: setuid/setgid/setresuid without "
        "setgroups, retaining supplementary groups, changing user but not group list",
        "local attacker via a spawned command",
    ),
    TaintQuery(
        "arg-injection", "CWE-88",
        "Argument injection into a CLI",
        "passing input as an argument to a CLI (git, gh, tar) where a leading-dash "
        "value becomes a flag; no `--` separator or leading-dash rejection",
        "repo/branch/remote name beginning with '-'",
    ),
    TaintQuery(
        "dos-unbounded", "CWE-400",
        "Unbounded resource consumption",
        "reading a request without a size limit, unbounded header/line read, "
        "thread-per-connection with no timeout, unbounded queue or allocation",
        "slow or oversized request from any peer",
    ),
    TaintQuery(
        "deserialization", "CWE-502",
        "Unsafe deserialization",
        "deserializing attacker-controlled bytes into objects: pickle, yaml.load, "
        "unpickling, native deserialize of a socket buffer",
        "socket buffer, uploaded blob, restore payload",
    ),
    TaintQuery(
        "insecure-token-handling", "CWE-598",
        "Secret placed in URL / history / referer",
        "embedding a token or secret in a URL path or query string that lands in "
        "browser history, referer headers, or server access logs",
        "any observer of the URL / logs",
    ),
]

AGENT_PROMPT_QUERIES: list[TaintQuery] = [
    TaintQuery(
        "agent-prompt-assembly", "CWE-77",
        "Untrusted content assembled into an agent prompt",
        "building the prompt or user message sent to an LLM coding agent from task "
        "text, issue/PR body, git diff, file contents, README, or MCP tool output; "
        "combine_prompt, append_prompt, system prompt construction",
        "attacker-controlled repo content, task description, issue text, tool output",
    ),
    TaintQuery(
        "agent-autoapprove", "CWE-250",
        "Agent runs with permissions auto-approved",
        "launching a coding agent with permission checks disabled or bypassed by "
        "default: bypass permissions mode, auto-approve tools, skip confirmation flag",
        "any prompt-injection that reaches the agent",
    ),
]

ALL_QUERIES = SINK_QUERIES + AGENT_PROMPT_QUERIES

@dataclass
class ArchQuery:
    id: str
    cwe: str
    title: str
    query: str
    question: str

ARCH_QUERIES: list[ArchQuery] = [
    ArchQuery(
        "missing-global-auth", "CWE-306",
        "No authentication on the API surface",
        "HTTP router and route definitions, middleware layers, request "
        "authentication or authorization, bearer token / session / API-key check, "
        "permission guard, .route() .nest() .layer(), Axum/Express/FastAPI setup",
        "Across these router and middleware files, is authentication or "
        "authorization actually enforced on the API routes that perform sensitive "
        "actions (config read/write, command execution, file access)? If NO auth "
        "layer, token check, or session guard is applied anywhere in the request "
        "path, that is a finding — the whole surface is unauthenticated. Only an "
        "Origin/Host check is NOT authentication.",
    ),
    ArchQuery(
        "secret-in-response", "CWE-200",
        "Secret serialized into an API response",
        "config or settings struct containing a token, secret, password, PAT, or "
        "oauth field; serde Serialize; an HTTP handler that returns the config or a "
        "user object as JSON (GET /info, GET /config, /me)",
        "Trace whether a secret/token/password field defined on a struct is "
        "returned to a client by any handler. A finding exists when a handler "
        "serializes an object whose type includes a credential field that is NOT "
        "redacted (no serde skip_serializing / no omission). Name the struct and "
        "the handler.",
    ),
    ArchQuery(
        "weak-origin-host", "CWE-346",
        "Incomplete cross-origin / DNS-rebinding protection",
        "CORS layer allow_origin, Origin header validation, Host header check, "
        "websocket upgrade origin check, same-origin comparison, validate_origin",
        "Is cross-origin protection complete against DNS-rebinding? A finding "
        "exists if the code allows requests with a missing Origin header, compares "
        "Origin to Host without also pinning Host to an allow-list of "
        "localhost/known hosts, or uses a permissive/reflected CORS origin. Explain "
        "the rebinding path if so.",
    ),
    ArchQuery(
        "agent-autoapprove-arch", "CWE-250",
        "Agents run with permissions bypassed by default",
        "coding agent launch, permission mode, bypass permissions, auto approve, "
        "dangerously skip permissions, default profile, sandbox mode, allow all tools",
        "Do the default settings launch the coding agent(s) with permission checks "
        "disabled or all tools auto-approved (so a prompt injection reaches an "
        "auto-approving agent)? Look across the executor and the default-profile "
        "config. A dangerous default that the user must opt OUT of is a finding.",
    ),
]
