# SIE Sentinel — project brief

Open-source LLMs finding vulnerabilities in open-source software. Every piece of
reasoning here runs on Superlinked's models (Qwen for analysis, gliguard for the
guardrail). Claude was the tool we wrote it with, not part of the product.

## What it does

Three tools, one control panel.

- **Scan** a repo for real, exploitable bugs, and only show the ones that survive a
  disprove-check.
- **Pen-test** those findings into reproducible proof-of-concepts and an attack chain.
- **Monitor** a live stream of agent input for prompt injection, and block it.

## Against the judging questions

**A major threat, and an emerging one.** The scanner finds unauthenticated command
execution, memory-exhaustion DoS, secret exposure, and — the emerging part — coding
agents that auto-approve every tool by default, which turns any injected instruction
in a repo into code running on the host. The monitor is the runtime answer to that
same threat.

**Does it work well.** Every finding is re-checked by a model told to disprove it,
and the cited line is verified against the source before it is shown. On a repo we
had reviewed by hand first, all three findings the scanner reported were real.

**Is it working.** The numbers below are from real runs.

## Results

**snare** (Rust webhook runner). We reviewed it by hand, then ran the scanner blind.
It found the same real issues: missing HMAC verification, command execution when no
secret is set, and an unbounded-header DoS. Three findings, all real.

**vibe-kanban** (AI coding-agent orchestrator, the main target). Five findings, no
false positives:

| Severity | CWE | Finding |
|---|---|---|
| Critical | CWE-306 | The whole local API has no authentication |
| Critical | CWE-250 | Default agent profiles auto-approve every tool |
| High | CWE-200 | GitHub token serialized into an API response |
| High | CWE-346 | Origin check has a DNS-rebinding gap |
| Medium | CWE-400 | Unbounded request-body buffering |

The two criticals and both highs are cross-file problems — a property of the router
and its middleware, or a struct in one file returned by a handler in another. A
per-chunk scanner cannot see them. The cross-file pass recovered all four.

**Monitor.** On a labelled set that includes base64, unicode, and translated
payloads: rules alone catch 64%, gliguard alone 45%, the three detectors together
catch 100% with no false positives.

## How the scan works

Seven steps, each on the smallest model that can do it.

1. Chunk and embed the repo — dense (Qwen3-Embedding-4B) and sparse (SPLADE), so
   both intent and exact identifiers are searchable.
2. Run CWE-tagged queries through hybrid search and a reranker (Qwen3-Reranker-4B).
3. Drop noise with a small model (Qwen3.5-4B).
4. Read the survivors with their surrounding code (Qwen3.8-27B).
5. Cross-file pass: bundle one chunk from each of several files and reason about the
   whole-system property.
6. Disprove-check plus a line-exists check. Fail either and it's dropped.
7. Write the report.

## What we measured, and where it stops

We scored recall against the bugs we found by hand. Overall it recovers about two
thirds of them; on vibe-kanban, all five. The gaps left are cross-file findings in
JavaScript and a couple of local-socket issues in a well-built daemon — the queries
today are shaped for Rust web services. That is the next thing to add, and we say so
rather than round the number up.

## Scope

Authorized, offline review of the practice repos we were given. No maintainer was
contacted, no live system touched, and no exploit was run. All findings stay in the
local reports.

## Running it

```bash
python sie_client.py                    # check the key and models
python scan.py targets\snare            # scan
python scan.py targets\vibe-kanban --include crates\server,crates\executors
python pentest.py targets\snare         # PoCs from the findings
python monitor.py --demo --action block # live injection blocking
python dashboard.py                     # all three at http://127.0.0.1:8765
python eval_scan.py                     # recall against known bugs
```
