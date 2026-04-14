# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

nano-analyzer is an LLM-powered zero-day vulnerability scanner by AISLE. It runs as a Claude Code skill — Claude Opus acts as both the orchestrator and the security analysis model, using native tools (Read, Grep, Glob, Agent subagents) instead of external API calls.

## Usage

```
/scan ./path/to/file.c                          # scan a single file
/scan ./path/to/src/                             # scan a directory
/scan ./src --triage-rounds 7                    # more triage rounds
/scan ./src --triage-threshold high              # only triage high+ findings
/scan ./src --no-triage                          # scan only, skip triage
/scan ./src --min-confidence 0.7                 # only report 70%+ confidence
```

No API keys, no Python dependencies, no build system needed. Claude Code IS the scanner.

## Architecture: Two-Stage Pipeline

### Stage 1: Scanning (Explore subagents)
- `python3 utils.py discover <path>` finds and bundles source files (deterministic, no LLM tokens)
- Explore subagents analyze each bundle: Read file, grep constants/callers, return JSON findings

### Stage 2: Skeptical Triage (sequential rounds)
- Each finding above the severity threshold gets 5 rounds of skeptical review
- Each round: a subagent with Grep/Read access evaluates the finding, sees prior rounds' reasoning
- Arbiter: orchestrator makes final VALID/INVALID call after reviewing all rounds
- `python3 utils.py output <dir> --scan-results ... --triage-results ...` writes all output files

## File Layout

```
utils.py                                # Deterministic helpers (discovery, bundling, output)
.claude/
  commands/scan.md                      # /scan entry point
  skills/nano-scan/
    SKILL.md                            # Orchestration flow referencing utils.py
    prompts/
      scan-agent.md                     # Per-file scan subagent prompt
      triage-round.md                   # Single triage round subagent prompt
```

## Output

Results written to `~/nano-analyzer-results/<timestamp>/`:
- `summary.md` / `summary.json` — scan overview
- `findings/VULN-NNN_<file>.md` — surviving findings with full triage reasoning
- `scan-log.md` — per-file scan results

## Key Design Decisions

- **Claude IS the model** — no external API calls, no API keys, no retry logic
- **Native tools** — Grep/Read replace subprocess ripgrep and text-parsing hacks
- **Subagents** — replace Python ThreadPoolExecutor for parallel scanning
- **Context gen eliminated** — Claude can Grep mid-analysis, so the separate context generation stage is folded into the scan
- **Opus-tuned prompts** — simpler than the original gpt-5.4-nano prompts, trusting Opus's stronger reasoning
