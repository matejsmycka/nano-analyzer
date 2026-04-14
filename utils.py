#!/usr/bin/env python3
"""
Utility helpers for nano-scan skill.
Handles deterministic, mechanical work so Claude can focus on security analysis.

Subcommands:
  discover   Walk a path, filter files, produce bundles as JSON
  output     Write summary/findings/scan-log from JSON results
"""

import argparse
import json
import os
import sys
from datetime import datetime

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_MAX_CHARS = 200_000

SOURCE_EXTENSIONS = {
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx",
    ".java", ".py", ".go", ".rs", ".js", ".ts", ".rb",
    ".swift", ".m", ".mm", ".cs", ".php", ".pl", ".sh",
}

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "informational"]

SEVERITY_EMOJI = {
    "critical": "\U0001f534",
    "high": "\U0001f7e0",
    "medium": "\U0001f7e1",
    "low": "\U0001f535",
    "informational": "\u26aa",
    "clean": "\U0001f7e2",
}

VERDICT_EMOJI = {
    "VALID": "\u2705",
    "INVALID": "\u274c",
    "UNCERTAIN": "\u2753",
    "ERROR": "\U0001f4a5",
}

# ---------------------------------------------------------------------------
# discover
# ---------------------------------------------------------------------------

def discover_files(path, max_chars):
    """Walk path, filter by extension/size, return scannable + skipped."""
    scannable = []
    skipped = []

    if os.path.isfile(path):
        candidates = [path]
    else:
        candidates = []
        for root, _, fnames in os.walk(path):
            for fn in sorted(fnames):
                candidates.append(os.path.join(root, fn))

    for filepath in candidates:
        if os.path.islink(filepath):
            skipped.append({"filepath": filepath, "reason": "symlink"})
            continue

        ext = os.path.splitext(filepath)[1].lower()
        if ext not in SOURCE_EXTENSIONS:
            skipped.append({"filepath": filepath, "reason": "extension"})
            continue

        try:
            size = os.path.getsize(filepath)
        except OSError:
            skipped.append({"filepath": filepath, "reason": "unreadable"})
            continue

        if size > max_chars:
            skipped.append({"filepath": filepath, "reason": f"too large ({size:,} bytes)"})
            continue

        try:
            with open(filepath) as f:
                content = f.read()
            line_count = content.count("\n")
            char_count = len(content)
        except (OSError, UnicodeDecodeError):
            skipped.append({"filepath": filepath, "reason": "unreadable/binary"})
            continue

        if char_count > max_chars:
            skipped.append({"filepath": filepath, "reason": f"too large ({char_count:,} chars)"})
            continue

        scannable.append({
            "filepath": filepath,
            "lines": line_count,
            "chars": char_count,
        })

    return scannable, skipped


def make_bundles(scannable):
    """Group files into bundles for subagent dispatch.
    Big files (>500 lines) go solo. Small files grouped 2-4 by directory."""
    solo = []
    by_dir = {}

    for f in scannable:
        if f["lines"] > 500:
            solo.append([f["filepath"]])
        else:
            d = os.path.dirname(f["filepath"])
            by_dir.setdefault(d, []).append(f["filepath"])

    grouped = []
    for d, files in by_dir.items():
        # Try to pair .c/.h files, then chunk remaining
        paired = {}
        rest = []
        for fp in files:
            stem = os.path.splitext(os.path.basename(fp))[0]
            paired.setdefault(stem, []).append(fp)

        for stem, group in paired.items():
            if len(group) >= 2:
                # Keep pairs together (e.g. foo.c + foo.h)
                grouped.append(group)
            else:
                rest.extend(group)

        # Chunk remaining into groups of 3
        for i in range(0, len(rest), 3):
            grouped.append(rest[i:i + 3])

    return solo + grouped


def cmd_discover(args):
    path = os.path.abspath(args.path)
    scannable, skipped = discover_files(path, args.max_chars)
    bundles = make_bundles(scannable)

    # Compute base path for display names
    if os.path.isdir(path):
        base = path
    else:
        base = os.path.dirname(path)

    for f in scannable:
        f["display_name"] = os.path.relpath(f["filepath"], base)

    result = {
        "target": path,
        "base_path": base,
        "total_files": len(scannable),
        "total_lines": sum(f["lines"] for f in scannable),
        "total_chars": sum(f["chars"] for f in scannable),
        "scannable": scannable,
        "bundles": bundles,
        "skipped_summary": {
            "total": len(skipped),
            "extension": sum(1 for s in skipped if s["reason"] == "extension"),
            "too_large": sum(1 for s in skipped if "large" in s["reason"]),
            "unreadable": sum(1 for s in skipped if "unreadable" in s["reason"]),
            "symlink": sum(1 for s in skipped if s["reason"] == "symlink"),
        },
    }
    json.dump(result, sys.stdout, indent=2)
    print()


# ---------------------------------------------------------------------------
# output
# ---------------------------------------------------------------------------

def compute_confidence(verdicts):
    """Compute confidence from a list of verdict strings."""
    if not verdicts:
        return 0.0, ""
    n_valid = sum(1 for v in verdicts if v == "VALID")
    verdicts_str = "".join(v[0] for v in verdicts)
    return round(n_valid / len(verdicts), 2), verdicts_str


def cmd_output(args):
    out_dir = args.output_dir
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(os.path.join(out_dir, "findings"), exist_ok=True)

    # Load scan results
    with open(args.scan_results) as f:
        scan_data = json.load(f)

    # Load triage results if provided
    triage_data = []
    if args.triage_results:
        with open(args.triage_results) as f:
            triage_data = json.load(f)

    min_conf = args.min_confidence
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Compute per-file severity counts
    file_results = scan_data.get("files", [])

    # Write scan-log.md
    with open(os.path.join(out_dir, "scan-log.md"), "w") as f:
        f.write("# Scan log\n\n")
        for fr in file_results:
            f.write(f"## {fr['display_name']}\n\n")
            findings = fr.get("findings", [])
            if not findings:
                f.write("Clean - no findings.\n\n")
            else:
                for fi in findings:
                    sev = fi.get("severity", "medium")
                    emoji = SEVERITY_EMOJI.get(sev, "")
                    f.write(f"- {emoji} **[{sev.upper()}]** {fi['title']}")
                    func = fi.get("function", "")
                    if func:
                        f.write(f" in `{func}`")
                    f.write(f"\n  {fi.get('description', '')}\n\n")

    # Process triage results
    survivors = []
    triage_valid = 0
    triage_invalid = 0
    triage_uncertain = 0

    for t in triage_data:
        rounds = t.get("rounds", [])
        arbiter = t.get("arbiter_verdict", "")
        all_verdicts = [r.get("verdict", "UNCERTAIN") for r in rounds]
        if arbiter:
            all_verdicts.append(arbiter)

        confidence, verdicts_str = compute_confidence(all_verdicts)
        if arbiter:
            # Reformat to show arbiter separately
            round_str = "".join(v[0] for v in [r.get("verdict", "U") for r in rounds])
            verdicts_str = f"{round_str}->{arbiter[0]}"

        t["confidence"] = confidence
        t["verdicts_str"] = verdicts_str

        final_verdict = arbiter if arbiter else (all_verdicts[-1] if all_verdicts else "UNCERTAIN")
        t["final_verdict"] = final_verdict

        if final_verdict == "VALID":
            triage_valid += 1
            if confidence >= min_conf:
                survivors.append(t)
        elif final_verdict == "INVALID":
            triage_invalid += 1
        else:
            triage_uncertain += 1

    # Sort survivors by confidence desc
    survivors.sort(key=lambda t: -t["confidence"])

    # Write finding files
    for idx, t in enumerate(survivors, 1):
        safename = t.get("file", "unknown").replace("/", "_").replace("\\", "_")
        finding_path = os.path.join(out_dir, "findings", f"VULN-{idx:03d}_{safename}.md")

        conf_pct = int(t["confidence"] * 100)
        with open(finding_path, "w") as f:
            f.write(f"# VULN-{idx:03d}: {t['title']}\n\n")
            f.write(f"- **File**: `{t.get('file', 'unknown')}`\n")
            f.write(f"- **Confidence**: {conf_pct}% [{t['verdicts_str']}]\n")
            f.write(f"- **Severity**: {t.get('severity', 'medium')}\n\n")
            f.write("---\n\n## Finding\n\n")
            f.write(t.get("description", "") + "\n\n")
            f.write("---\n\n## Triage rounds\n\n")
            for ri, rv in enumerate(t.get("rounds", []), 1):
                v = rv.get("verdict", "UNCERTAIN")
                emoji = VERDICT_EMOJI.get(v, "\u2753")
                f.write(f"### Round {ri}: {emoji} {v}\n\n")
                f.write(rv.get("reasoning", "") + "\n\n")
                crux = rv.get("crux", "")
                if crux:
                    f.write(f"**Crux:** {crux}\n\n")
            if t.get("arbiter_reasoning"):
                av = t.get("arbiter_verdict", "UNCERTAIN")
                emoji = VERDICT_EMOJI.get(av, "\u2753")
                f.write(f"### Arbiter: {emoji} {av}\n\n")
                f.write(t["arbiter_reasoning"] + "\n\n")

        t["finding_path"] = finding_path

    # Severity counts across all files
    sev_counts = {s: 0 for s in SEVERITY_LEVELS}
    for fr in file_results:
        for fi in fr.get("findings", []):
            sev = fi.get("severity", "medium")
            if sev in sev_counts:
                sev_counts[sev] += 1

    crit_files = sum(1 for fr in file_results if any(f.get("severity") == "critical" for f in fr.get("findings", [])))
    high_files = sum(1 for fr in file_results if any(f.get("severity") == "high" for f in fr.get("findings", [])))
    med_files = sum(1 for fr in file_results if any(f.get("severity") == "medium" for f in fr.get("findings", [])))
    clean_files = sum(1 for fr in file_results if not fr.get("findings"))
    error_files = sum(1 for fr in file_results if fr.get("status") == "error")

    # Write summary.md
    total_lines = sum(fr.get("lines", 0) for fr in file_results)
    with open(os.path.join(out_dir, "summary.md"), "w") as f:
        f.write("# nano-scan results\n\n")
        f.write(f"- **Target**: `{scan_data.get('target', '')}`\n")
        f.write(f"- **Date**: {timestamp}\n")
        f.write(f"- **Files scanned**: {len(file_results)} ({total_lines:,} lines)\n\n")

        f.write("| File | Lines | Critical | High | Medium | Low |\n")
        f.write("|------|-------|----------|------|--------|-----|\n")
        for fr in file_results:
            fc = {s: 0 for s in SEVERITY_LEVELS}
            for fi in fr.get("findings", []):
                s = fi.get("severity", "medium")
                if s in fc:
                    fc[s] += 1
            f.write(f"| {fr['display_name']} | {fr.get('lines', 0)} "
                    f"| {fc['critical']} | {fc['high']} | {fc['medium']} | {fc['low']} |\n")

        if triage_data:
            f.write(f"\n## Triage summary\n\n")
            f.write(f"- {VERDICT_EMOJI['VALID']} Valid: {triage_valid} | "
                    f"{VERDICT_EMOJI['INVALID']} Rejected: {triage_invalid} | "
                    f"{VERDICT_EMOJI['UNCERTAIN']} Uncertain: {triage_uncertain}\n\n")

            if survivors:
                f.write("## Findings that survived triage\n\n")
                for idx, t in enumerate(survivors, 1):
                    conf_pct = int(t["confidence"] * 100)
                    f.write(f"- **VULN-{idx:03d}** {conf_pct}% [{t['verdicts_str']}] "
                            f"`{t.get('file', '')}`: {t['title']}\n")

    # Write summary.json
    summary = {
        "target": scan_data.get("target", ""),
        "timestamp": timestamp,
        "files_scanned": len(file_results),
        "total_lines": total_lines,
        "severity_counts": sev_counts,
        "critical_files": crit_files,
        "high_files": high_files,
        "medium_files": med_files,
        "clean_files": clean_files,
        "error_files": error_files,
        "triage": {
            "valid": triage_valid,
            "invalid": triage_invalid,
            "uncertain": triage_uncertain,
        } if triage_data else None,
        "survivors": [
            {
                "vuln_id": f"VULN-{i+1:03d}",
                "title": t["title"],
                "file": t.get("file", ""),
                "severity": t.get("severity", "medium"),
                "confidence": t["confidence"],
                "verdicts": t["verdicts_str"],
            }
            for i, t in enumerate(survivors)
        ],
        "per_file": [
            {
                "file": fr["display_name"],
                "lines": fr.get("lines", 0),
                "findings": len(fr.get("findings", [])),
                "status": fr.get("status", "ok"),
            }
            for fr in file_results
        ],
    }
    with open(os.path.join(out_dir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    # Print console summary
    print(f"Summary: {len(file_results)} files scanned")
    if crit_files:
        print(f"  {SEVERITY_EMOJI['critical']} Critical: {crit_files} files ({sev_counts['critical']} findings)")
    if high_files:
        print(f"  {SEVERITY_EMOJI['high']} High: {high_files} files ({sev_counts['high']} findings)")
    if med_files:
        print(f"  {SEVERITY_EMOJI['medium']} Medium: {med_files} files ({sev_counts['medium']} findings)")
    print(f"  {SEVERITY_EMOJI['clean']} Clean: {clean_files} files")
    if error_files:
        print(f"  Error: {error_files} files")

    if triage_data:
        print(f"\nTriage: {VERDICT_EMOJI['VALID']} {triage_valid} valid | "
              f"{VERDICT_EMOJI['INVALID']} {triage_invalid} rejected | "
              f"{VERDICT_EMOJI['UNCERTAIN']} {triage_uncertain} uncertain")
        if survivors:
            print("\nFindings that survived triage:")
            for idx, t in enumerate(survivors, 1):
                conf_pct = int(t["confidence"] * 100)
                print(f"  {conf_pct}% [{t['verdicts_str']}] {t.get('file', '')}: {t['title']}")
                if t.get("finding_path"):
                    print(f"     -> {t['finding_path']}")

    print(f"\nResults saved to: {out_dir}/")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(prog="utils", description="nano-scan utility helpers")
    sub = parser.add_subparsers(dest="command")

    # discover
    p_disc = sub.add_parser("discover", help="Discover and bundle source files")
    p_disc.add_argument("path", help="File or directory to scan")
    p_disc.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS,
                        help=f"Skip files larger than this (default: {DEFAULT_MAX_CHARS:,})")

    # output
    p_out = sub.add_parser("output", help="Generate output files from scan/triage results")
    p_out.add_argument("output_dir", help="Output directory")
    p_out.add_argument("--scan-results", required=True, help="Path to scan results JSON")
    p_out.add_argument("--triage-results", default=None, help="Path to triage results JSON")
    p_out.add_argument("--min-confidence", type=float, default=0.0,
                        help="Only include findings above this confidence (0.0-1.0)")

    args = parser.parse_args()
    if args.command == "discover":
        cmd_discover(args)
    elif args.command == "output":
        cmd_output(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
