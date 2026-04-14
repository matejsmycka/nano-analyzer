Scan $ARGUMENTS for zero-day security vulnerabilities.

Start immediately — do NOT ask the user for a path. The target is: $ARGUMENTS

## Step 1: Discovery

Run this command to discover and bundle source files:

```
python3 utils.py discover $ARGUMENTS
```

Print a summary of what was found.

## Step 2: Scanning

The discovery JSON has a `bundles` field — each bundle is a **list of file path strings**, e.g. `["/tmp/foo/bar.c", "/tmp/foo/bar.h"]`. It is NOT a dict.

For each bundle, read .claude/skills/nano-scan/prompts/scan-agent.md and dispatch a **haiku** Explore subagent with that prompt, substituting:
- `{files}` — the file paths from the bundle (the list of strings)
- `{repo_dir}` — the `base_path` from the discovery JSON

Dispatch up to 3 subagents in parallel. Always use model: "haiku" for scan subagents.

Collect all findings (JSON arrays of {severity, title, function, description}).

## Step 3: Triage

For each finding at medium severity or above, run 5 sequential triage rounds. Read .claude/skills/nano-scan/prompts/triage-round.md for the subagent prompt. Dispatch each round as a **sonnet** general-purpose subagent (model: "sonnet"). Each round sees prior rounds' reasoning. After 5 rounds, make a final VALID/INVALID arbiter decision yourself.

## Step 4: Output

Save scan results to /tmp/nano-scan-results.json and triage results to /tmp/nano-triage-results.json, then run:

```
python3 utils.py output ~/nano-analyzer-results/$(date +%Y-%m-%d_%H%M%S) --scan-results /tmp/nano-scan-results.json --triage-results /tmp/nano-triage-results.json
```
