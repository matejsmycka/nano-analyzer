---
name: nano-scan
description: Scan source code for zero-day security vulnerabilities. Use when the user asks to scan files or directories for vulnerabilities, security bugs, memory safety issues, or run nano-analyzer. Primarily targets C/C++ memory safety bugs but supports many languages.
---

# nano-scan

LLM-powered zero-day vulnerability scanner. Two-stage pipeline:
1. **Scan** — Explore subagents read and analyze source files using Grep/Read tools for verification
2. **Triage** — sequential skeptical review rounds with Grep verification, then arbiter decision

Uses `utils.py` for deterministic mechanical work (file discovery, bundling, output generation) to save tokens.

## Phase 1: Discovery

Run:
```bash
python3 utils.py discover <path> [--max-chars N]
```

This outputs JSON with:
- `scannable` — list of `{filepath, lines, chars, display_name}`
- `bundles` — grouped file paths ready for subagent dispatch
- `skipped_summary` — counts by reason
- `total_files`, `total_lines`, `total_chars`

Print a summary:
```
Nano-scan vulnerability scanner
Target: /path/to/target
N files to scan (X lines, Y chars)
Skipped: N wrong extension, N too large, N unreadable
```

## Phase 2: Scanning

Read the scan subagent prompt from `prompts/scan-agent.md`.

For each bundle from the discovery JSON:

1. Construct the subagent prompt by substituting into `prompts/scan-agent.md`:
   - `{files}` — the file paths in this bundle
   - `{repo_dir}` — the root directory for Grep searches (= `base_path` from discovery)
2. Dispatch as an **Explore** subagent with **model: "haiku"**
3. Dispatch up to 3 subagents in parallel per wave

Each subagent returns a JSON array of findings:
```json
[{"severity": "critical", "title": "...", "function": "...", "description": "..."}]
```

If a subagent returns no findings or reports the file is clean, record it as clean.

### Collecting results

After all waves complete, build a scan results JSON file and save it to a temp file:
```json
{
  "target": "/path/to/target",
  "files": [
    {
      "filepath": "...",
      "display_name": "...",
      "lines": 100,
      "chars": 5000,
      "status": "ok",
      "findings": [
        {"severity": "...", "title": "...", "function": "...", "description": "..."}
      ]
    }
  ]
}
```

Save this to `/tmp/nano-scan-results.json`.

## Phase 3: Triage

Skip this phase if `--no-triage` was specified.

Severity levels in order: critical, high, medium, low, informational.
Default triage threshold: medium (triage findings at medium severity or above).

For each finding at or above the triage threshold severity:

### 5-round sequential triage

Read the triage prompt from `prompts/triage-round.md`.

**Round 1:** Dispatch a general-purpose subagent with **model: "sonnet"** and the triage prompt, substituting:
- `{finding}` — the finding title + severity + description
- `{filepath}` — the source file path (the agent will Read it itself)
- `{repo_dir}` — the root directory for Grep searches
- `{prior_reasoning}` — empty for round 1

The subagent returns JSON: `{"verdict": "...", "reasoning": "...", "crux": "..."}`

**Rounds 2-5:** Dispatch with the same prompt, but set `{prior_reasoning}` to:
```
Prior reviewers have weighed in below. Their reasoning is SPECULATIVE — it may contain errors.
Your job is NOT to repeat their analysis. Instead:
- Find arguments they MISSED
- If they all focused on one aspect, look at a DIFFERENT one
- Verify any cited defense with actual values (use Grep)
- Do NOT rehash the same argument — add new information

Reviewer 1 (VALID):
reasoning text...

Reviewer 2 (INVALID):
reasoning text...
```

### Arbiter decision

After 5 rounds, review all verdicts and reasoning yourself. Make a final VALID or INVALID call. If all 5 rounds said INVALID/UNCERTAIN and you see no overwhelming contrary evidence, mark INVALID.

### Building triage results

For each triaged finding, build:
```json
{
  "title": "finding title",
  "file": "display_name",
  "severity": "high",
  "description": "finding description",
  "rounds": [
    {"verdict": "VALID", "reasoning": "...", "crux": "..."},
    {"verdict": "INVALID", "reasoning": "...", "crux": "..."},
    ...
  ],
  "arbiter_verdict": "VALID",
  "arbiter_reasoning": "..."
}
```

Collect all triage results into an array and save to `/tmp/nano-triage-results.json`.

## Phase 4: Output

Create the output directory:
```bash
mkdir -p ~/nano-analyzer-results/$(date +%Y-%m-%d_%H%M%S)
```

Then run:
```bash
python3 utils.py output ~/nano-analyzer-results/<timestamp> \
  --scan-results /tmp/nano-scan-results.json \
  --triage-results /tmp/nano-triage-results.json \
  --min-confidence 0.0
```

This generates all output files:
- `summary.md` — human-readable overview with severity table
- `summary.json` — machine-readable
- `scan-log.md` — full per-file scan results
- `findings/VULN-NNN_<file>.md` — surviving findings with full triage reasoning

The command prints a console summary. Relay it to the user.

Clean up temp files:
```bash
rm -f /tmp/nano-scan-results.json /tmp/nano-triage-results.json
```
