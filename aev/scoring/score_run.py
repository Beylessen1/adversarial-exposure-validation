"""
aev.scoring.score_run
=====================
CLI entrypoint for the deterministic log scorer.

Single run:
    python3 -m aev.scoring.score_run \\
        --run runs/340b1c02.jsonl \\
        --sysmon /var/log/sysmon/sysmon.jsonl \\
        --output scores/340b1c02_score.json \\
        --report docs/findings_report.md

Corpus (all runs in a directory):
    python3 -m aev.scoring.score_run \\
        --runs-dir runs/ \\
        --sysmon /var/log/sysmon/sysmon.jsonl \\
        --corpus-output scores/corpus_summary.json \\
        --corpus-report docs/corpus_report.md
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .log_parser       import parse_run, parse_runs_dir, parse_sysmon_evtx, parse_sysmon_jsonl
from .detection_rules  import score_run
from .report_generator import (
    generate_run_report,
    generate_corpus_report,
    generate_console_table,
    export_score_json,
    export_corpus_json,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("aev.scoring")


def _load_sysmon(path: str | None, run=None):
    if not path:
        log.info("No Sysmon telemetry provided — sysmon_score will be 0.0")
        return []
    p = Path(path)
    if not p.exists():
        log.warning("Sysmon path not found: %s", path)
        return []
    start = run.start_ts if run else None
    end   = run.end_ts   if run else None
    if p.suffix.lower() == ".evtx":
        return parse_sysmon_evtx(p, start=start, end=end)
    return parse_sysmon_jsonl(p, start=start, end=end)


def cmd_single(args: argparse.Namespace) -> None:
    log.info("Parsing run: %s", args.run)
    run = parse_run(args.run)

    log.info("Loading Sysmon telemetry…")
    events = _load_sysmon(args.sysmon, run)
    log.info("Loaded %d Sysmon events", len(events))

    score = score_run(run, events)

    # Console output
    print(generate_console_table(score))

    # JSON output
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        export_score_json(score, args.output)
        log.info("Score JSON → %s", args.output)

    # Markdown report
    if args.report:
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        md = generate_run_report(score, run)
        Path(args.report).write_text(md)
        log.info("Markdown report → %s", args.report)

    # Print JSON to stdout if no output file
    if not args.output:
        print(json.dumps(score.summary_dict(), indent=2))


def cmd_corpus(args: argparse.Namespace) -> None:
    log.info("Parsing runs directory: %s", args.runs_dir)
    runs = parse_runs_dir(args.runs_dir)
    log.info("Found %d run(s)", len(runs))
    if not runs:
        log.error("No runs found — exiting")
        sys.exit(1)

    scores = []
    for run in runs:
        events = _load_sysmon(args.sysmon, run)
        s = score_run(run, events)
        scores.append(s)
        print(generate_console_table(s))

    if args.corpus_output:
        Path(args.corpus_output).parent.mkdir(parents=True, exist_ok=True)
        export_corpus_json(scores, args.corpus_output)
        log.info("Corpus JSON → %s", args.corpus_output)

    if args.corpus_report:
        Path(args.corpus_report).parent.mkdir(parents=True, exist_ok=True)
        md = generate_corpus_report(scores)
        Path(args.corpus_report).write_text(md)
        log.info("Corpus Markdown → %s", args.corpus_report)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AEV deterministic log scorer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="cmd")

    # ── single run ────────────────────────────────────────────────────────────
    p_single = sub.add_parser("single", help="Score one run JSONL file")
    p_single.add_argument("--run",     required=True, help="Path to run JSONL (runs/*.jsonl)")
    p_single.add_argument("--sysmon",  default=None,  help="Sysmon telemetry (.evtx or .jsonl)")
    p_single.add_argument("--output",  default=None,  help="Output score JSON path")
    p_single.add_argument("--report",  default=None,  help="Output Markdown report path")

    # ── corpus ────────────────────────────────────────────────────────────────
    p_corpus = sub.add_parser("corpus", help="Score all runs in a directory")
    p_corpus.add_argument("--runs-dir",      required=True, help="Directory containing run JSONL files")
    p_corpus.add_argument("--sysmon",        default=None,  help="Sysmon telemetry (.evtx or .jsonl)")
    p_corpus.add_argument("--corpus-output", default=None,  help="Output corpus JSON path")
    p_corpus.add_argument("--corpus-report", default=None,  help="Output corpus Markdown path")

    args = parser.parse_args()

    # Backwards-compatible: if called with --run directly (no subcommand)
    if args.cmd is None:
        # Re-parse as single
        parser2 = argparse.ArgumentParser()
        parser2.add_argument("--run",      default=None)
        parser2.add_argument("--runs-dir", default=None)
        parser2.add_argument("--sysmon",   default=None)
        parser2.add_argument("--output",   default=None)
        parser2.add_argument("--report",   default=None)
        parser2.add_argument("--corpus-output", default=None)
        parser2.add_argument("--corpus-report", default=None)
        args2 = parser2.parse_args()
        if args2.run:
            args2.cmd = "single"
            cmd_single(args2)
        elif args2.runs_dir:
            args2.cmd = "corpus"
            cmd_corpus(args2)
        else:
            parser.print_help()
        return

    if args.cmd == "single":
        cmd_single(args)
    elif args.cmd == "corpus":
        cmd_corpus(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()