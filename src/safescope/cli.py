"""Command line interface: ``safescope scan example.com``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from safescope._version import __version__
from safescope.checks import ALL_CHECKS, Check, get_checks
from safescope.http import HttpClient
from safescope.models import Severity
from safescope.reporters import REPORTERS
from safescope.reporters.console import render_console
from safescope.scanner import Scanner

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_UNREACHABLE = 3

EPILOG = """\
examples:
  safescope scan example.com
  safescope scan https://example.com -f html -o report.html
  safescope scan example.com --only headers,cookies -f json
  safescope scan staging.example.com --fail-on medium   # for CI pipelines

exit codes: 0 ok, 1 findings at/above --fail-on, 2 usage error, 3 target unreachable
Only scan systems you own or have explicit permission to test.
"""


def _csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safescope",
        description="Safe, non-intrusive web security posture scanner.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"SafeScope {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    scan = sub.add_parser("scan", help="scan a website", epilog=EPILOG,
                          formatter_class=argparse.RawDescriptionHelpFormatter)
    scan.add_argument("target", help="URL or host name, e.g. example.com or https://example.com/app")
    scan.add_argument("-f", "--format", choices=sorted(REPORTERS), default="console",
                      help="output format (default: console)")
    scan.add_argument("-o", "--output", type=Path, help="write the report to a file instead of stdout")
    scan.add_argument("--only", type=_csv, metavar="IDS", help="comma separated checks to run")
    scan.add_argument("--skip", type=_csv, metavar="IDS", help="comma separated checks to skip")
    scan.add_argument("--timeout", type=float, default=10.0, help="network timeout in seconds (default: 10)")
    scan.add_argument("--fail-on", metavar="SEVERITY", type=Severity.parse,
                      help="exit with code 1 if an issue of this severity or higher is found "
                           "(info, low, medium, high, critical)")
    scan.add_argument("--no-color", action="store_true", help="disable coloured console output")
    scan.add_argument("-v", "--verbose", action="store_true", help="show evidence for passed checks too")
    scan.add_argument("-q", "--quiet", action="store_true", help="no progress messages on stderr")

    sub.add_parser("checks", help="list available checks")
    return parser


def _list_checks() -> int:
    width = max(len(c.id) for c in ALL_CHECKS)
    for cls in ALL_CHECKS:
        print(f"{cls.id.ljust(width)}  {cls.name} — {cls.description}")
    return EXIT_OK


def _run_scan(args: argparse.Namespace) -> int:
    try:
        checks = get_checks(args.only, args.skip)
    except ValueError as exc:
        print(f"safescope: error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    def progress(check: Check) -> None:
        if not args.quiet and sys.stderr.isatty():
            print(f"\r\033[K  running {check.name}…", end="", file=sys.stderr, flush=True)

    scanner = Scanner(checks=checks, client=HttpClient(timeout=args.timeout), on_check_start=progress)
    try:
        result = scanner.scan(args.target)
    except ValueError as exc:
        print(f"safescope: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    finally:
        if not args.quiet and sys.stderr.isatty():
            print("\r\033[K", end="", file=sys.stderr, flush=True)

    if "error" in result.metadata:
        print(f"safescope: could not reach {result.target}: {result.metadata['error']}", file=sys.stderr)
        return EXIT_UNREACHABLE

    if args.format == "console":
        use_color = False if (args.no_color or args.output) else None
        report = render_console(result, color=use_color, verbose=args.verbose)
    else:
        report = REPORTERS[args.format](result)

    if args.output:
        args.output.write_text(report, encoding="utf-8")
        if not args.quiet:
            print(f"Report written to {args.output} (grade {result.grade}, score {result.score}/100)",
                  file=sys.stderr)
    else:
        sys.stdout.write(report)

    worst = result.max_severity()
    if args.fail_on is not None and worst is not None and worst >= args.fail_on:
        return EXIT_FINDINGS
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "checks":
        return _list_checks()
    if args.command == "scan":
        return _run_scan(args)
    parser.print_help()
    return EXIT_USAGE
