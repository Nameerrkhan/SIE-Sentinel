# SIE Sentinel

Three security tools that run on Superlinked's open-source models. No OpenAI or
Anthropic model does any of the reasoning.

- `scan.py` finds and validates vulnerabilities in a repo.
- `pentest.py` turns those findings into proof-of-concepts and an attack chain.
- `monitor.py` watches a live stream of agent input for prompt injection.
- `dashboard.py` puts all three behind one local page.

Everything talks to hosted SIE at `https://api.superlinked.com`, or to a local
`sie-server` if you change `SIE_BASE_URL`.

## Setup

```bash
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
copy .env.example .env
```

Put your key in `.env`:

```
SIE_API_KEY=sk-sie-...
```

Check it works:

```bash
python sie_client.py
```

You should see `"encode_check": "OK (2560-dim)"`.

## Scanning a repo

```bash
python scan.py path\to\repo
python scan.py path\to\repo --include crates/server,crates/executors   # scope a big repo
python scan.py path\to\repo --ensemble 3                               # vote across 3 passes
python scan.py path\to\repo --pentest                                  # scan, then write PoCs
```

The scan runs in stages, each on the cheapest model that can do the job:

1. Chunk the repo and embed it (dense with Qwen3-Embedding-4B, sparse with SPLADE).
2. Run a set of CWE-tagged queries through hybrid search and a reranker.
3. Drop the obvious noise with a small model (Qwen3.5-4B).
4. Read the survivors closely with the surrounding code (Qwen3.8-27B).
5. Run a cross-file pass that reasons over several files at once — this is what
   catches "there is no auth anywhere" or "a secret defined here is returned there".
6. Re-check every finding with a model told to disprove it, and confirm the cited
   line exists in the source. Anything that fails is dropped.

Reports land in `path\to\repo\.sie_scan\` as Markdown and JSON.

## Pen-test report

```bash
python pentest.py path\to\repo
python pentest.py path\to\repo --min-severity high
```

For each finding it writes preconditions, steps, a runnable PoC, a CVSS vector, and
the fix, then chains the findings into one attack narrative. It pulls real routes
and symbols out of the code so the PoC uses them, and checks any path the PoC cites
against the source so a made-up endpoint gets flagged instead of shipped as fact.

Nothing runs. The PoCs are written for you to try against a local copy you own.

## Monitor

```bash
python monitor.py --demo                          # synthetic benign + attack traffic
python monitor.py --repo path\to\repo             # read a repo's docs for a planted payload
python monitor.py --file events.jsonl --follow    # tail a live log
type events.jsonl | python monitor.py             # stdin
```

Each event is scored three ways: the gliguard model, a set of signature rules, and
a Qwen judge that only runs on the close calls. That mix matters — on a test set
with encoded and translated payloads, the rules alone catch 64%, gliguard alone
45%, and the three together 100% with no false positives. Add `--action block` to
mark hits as blocked, `--explain` for a one-line reason per alert.

Events are JSON lines with a `text` field (or point at another field with
`--field`). Alerts also append to `monitor-alerts.jsonl`.

## Dashboard

```bash
python dashboard.py        # open http://127.0.0.1:8765
```

One page for all three tools. Pick a repo and run a scan while the log streams;
generate PoCs from a scan; start the monitor on demo traffic or a repo's docs and
watch the feed. It runs the same scripts as subprocesses, so it needs to be local
(the tools use your key and read the repos on disk).

## Measuring it

```bash
python eval_scan.py       # scan recall vs vulnerabilities found by hand
python eval_monitor.py    # monitor detection vs a set of evasions
```

`eval_scan.py` holds the vulnerabilities we found reviewing the target repos by
hand and reports how many the scanner recovers. With the cross-file pass on,
vibe-kanban goes from 1 of 5 to 5 of 5.

## MCP server

`sie_code_mcp.py` exposes the same SIE tools to Claude Code for interactive work
(search a codebase, check a string for injection, reason over specific chunks).

Register it as an MCP server in Claude Code, pointing at the venv's Python and
`sie_code_mcp.py`. Then restart Claude Code, run `/mcp`, and ask it to run
`sie_health` first.

## Scope

For authorized, offline review of code you own or have permission to test. The
tools read source and write reports. They do not contact maintainers, touch live
systems, or run any exploit.

## Config

All model names and limits are environment variables with sensible defaults — see
`.env.example`. Point `SIE_BASE_URL` at a local `sie-server` to run without the
hosted API.
