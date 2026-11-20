"""Command line interface: ``safescope scan example.com``."""

from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from collections.abc import Sequence
from pathlib import Path

from safescope._version import __version__
from safescope.checks import ALL_CHECKS, get_checks
from safescope.http import HttpClient
from safescope.models import SCHEMA_VERSION, ScanResult, Severity
from safescope.reporters import REPORTERS
from safescope.reporters.console import render_console
from safescope.reporters.sarif import render_sarif_many
from safescope.scanner import Scanner

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_UNREACHABLE = 3
MAX_CONCURRENCY = 16

EPILOG = """\
examples:
  safescope scan example.com
  safescope scan https://example.com -f html -o report.html
  safescope scan example.com --only headers,cookies -f json
  safescope scan staging.example.com --fail-on medium   # for CI pipelines
  safescope scan a.com b.com --targets-file sites.txt   # several sites, 4 at a time
  safescope scan example.com -f sarif -o safescope.sarif
  safescope report scan.json -f html -o report.html     # re-render a saved scan
  safescope serve                                       # web UI on http://127.0.0.1:8000

exit codes: 0 ok, 1 findings at/above --fail-on, 2 usage error, 3 a target was unreachable
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

    scan = sub.add_parser(
        "scan", help="scan a website", epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    scan.add_argument("targets", nargs="*", metavar="TARGET", help="URLs or host names, e.g. example.com")
    scan.add_argument("--targets-file", metavar="FILE", help="read more targets from FILE, one per line (# comments)")
    scan.add_argument(
        "--concurrency",
        type=int,
        default=4,
        help=f"how many targets to scan at once (1-{MAX_CONCURRENCY}, default: 4)",
    )
    scan.add_argument(
        "--max-time", type=float, metavar="SECONDS", help="stop a scan of one target after this many seconds"
    )
    scan.add_argument(
        "-f", "--format", choices=sorted(REPORTERS), default="console", help="output format (default: console)"
    )
    scan.add_argument("-o", "--output", type=Path, help="write the report to a file instead of stdout")
    scan.add_argument("--only", type=_csv, metavar="IDS", help="comma separated checks to run")
    scan.add_argument("--skip", type=_csv, metavar="IDS", help="comma separated checks to skip")
    scan.add_argument("--timeout", type=float, default=10.0, help="network timeout in seconds (default: 10)")
    scan.add_argument(
        "--fail-on",
        metavar="SEVERITY",
        type=Severity.parse,
        help="exit with code 1 if an issue of this severity or higher is found (info, low, medium, high, critical)",
    )
    scan.add_argument("--no-color", action="store_true", help="disable coloured console output")
    scan.add_argument("-v", "--verbose", action="store_true", help="show evidence for passed checks too")
    scan.add_argument("-q", "--quiet", action="store_true", help="no progress messages on stderr")
    scan.add_argument(
        "--public-only",
        action="store_true",
        help="refuse targets (and redirects) that resolve to private/internal addresses",
    )

    sub.add_parser("checks", help="list available checks")

    report = sub.add_parser("report", help="re-render a saved JSON report in another format")
    report.add_argument("file", help="a JSON report written by 'safescope scan -f json'")
    report.add_argument("-f", "--format", choices=sorted(REPORTERS), default="console")
    report.add_argument("-o", "--output", type=Path, help="write to a file instead of stdout")
    report.add_argument("--no-color", action="store_true")
    report.add_argument("-v", "--verbose", action="store_true")

    serve = sub.add_parser("serve", help="run the web UI and JSON API locally")
    serve.add_argument("--host", default="127.0.0.1", help="interface to bind (default: 127.0.0.1)")
    serve.add_argument("--port", type=int, default=8000, help="port (default: 8000)")
    serve.add_argument(
        "--trust-proxy",
        action="store_true",
        help="use X-Forwarded-For for rate limiting; only behind a proxy that overwrites it",
    )
    return parser


def _list_checks() -> int:
    width = max(len(c.id) for c in ALL_CHECKS)
    for cls in ALL_CHECKS:
        print(f"{cls.id.ljust(width)}  {cls.name} — {cls.description}")
    return EXIT_OK


def _read_targets(args: argparse.Namespace) -> list[str]:
    targets = list(args.targets)
    if args.targets_file:
        text = Path(args.targets_file).read_text(encoding="utf-8")
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                targets.append(line)
    return targets


def _render_many(results: list[ScanResult], fmt: str, color: bool | None, verbose: bool) -> str:
    """Render one or more results. Multi-target JSON/SARIF stay a single valid document."""
    if fmt == "console":
        return "\n".join(render_console(r, color=color, verbose=verbose) for r in results)
    if len(results) == 1:
        return REPORTERS[fmt](results[0])
    if fmt == "json":
        doc = {
            "schema_version": SCHEMA_VERSION,
            "tool": {"name": "SafeScope", "version": __version__},
            "results": [r.to_dict() for r in results],
        }
        return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    if fmt == "sarif":
        return render_sarif_many(results)
    if fmt == "markdown":
        return "\n".join(REPORTERS[fmt](r) for r in results)
    raise ValueError(f"the {fmt} format supports one target per report; use -f json and 'safescope report'")


def _run_scan(args: argparse.Namespace) -> int:
    try:
        checks = get_checks(args.only, args.skip)
        targets = _read_targets(args)
    except (ValueError, OSError) as exc:
        print(f"safescope: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if not targets:
        print("safescope: error: give at least one target (or --targets-file)", file=sys.stderr)
        return EXIT_USAGE
    if len(targets) > 1 and args.format == "html":
        print("safescope: error: HTML reports cover one target; use -f json, then 'safescope report'", file=sys.stderr)
        return EXIT_USAGE
    if not 1 <= args.concurrency <= MAX_CONCURRENCY:
        print(f"safescope: error: --concurrency must be between 1 and {MAX_CONCURRENCY}", file=sys.stderr)
        return EXIT_USAGE

    show_progress = not args.quiet and sys.stderr.isatty()
    guard = None
    if args.public_only:
        from safescope.netguard import assert_public_url

        guard = assert_public_url

    def scan_one(target: str) -> ScanResult:
        # A fresh client per target: each scan gets its own time budget.
        client = HttpClient(timeout=args.timeout, url_guard=guard, budget=args.max_time)
        return Scanner(checks=get_checks(args.only, args.skip), client=client).scan(target)

    results: list[ScanResult] = []
    unreachable = 0
    try:
        if len(targets) == 1:
            if show_progress:
                print(f"\r\033[K  scanning {targets[0]} ({len(checks)} checks)…", end="", file=sys.stderr, flush=True)
            scanned = [scan_one(targets[0])]
        else:
            with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
                futures = [pool.submit(scan_one, t) for t in targets]
                scanned = []
                for done, future in enumerate(futures, 1):
                    scanned.append(future.result())
                    if show_progress:
                        print(f"\r\033[K  {done}/{len(targets)} scanned…", end="", file=sys.stderr, flush=True)
    except ValueError as exc:
        print(f"safescope: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    finally:
        if show_progress:
            print("\r\033[K", end="", file=sys.stderr, flush=True)

    for result in scanned:
        if "error" in result.metadata:
            unreachable += 1
            print(f"safescope: could not reach {result.target}: {result.metadata['error']}", file=sys.stderr)
        else:
            results.append(result)
    if not results:
        return EXIT_UNREACHABLE

    use_color = False if (args.no_color or args.output) else None
    report = _render_many(results, args.format, use_color, args.verbose)
    if args.output:
        args.output.write_text(report, encoding="utf-8")
        if not args.quiet:
            grades = ", ".join(f"{r.target} {r.grade}" for r in results)
            print(f"Report written to {args.output} ({grades})", file=sys.stderr)
    else:
        sys.stdout.write(report)

    severities = [sev for sev in (r.max_severity() for r in results) if sev is not None]
    worst = max(severities, default=None)
    if args.fail_on is not None and worst is not None and worst >= args.fail_on:
        return EXIT_FINDINGS
    return EXIT_UNREACHABLE if unreachable else EXIT_OK


def _run_report(args: argparse.Namespace) -> int:
    """Re-render a saved JSON report (single or multi-target) in another format."""
    try:
        data = json.loads(Path(args.file).read_text(encoding="utf-8"))
        docs = data["results"] if isinstance(data, dict) and "results" in data else [data]
        results = [ScanResult.from_dict(d) for d in docs]
        report = _render_many(results, args.format, False if (args.no_color or args.output) else None, args.verbose)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"safescope: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if args.output:
        args.output.write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "checks":
        return _list_checks()
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "report":
        return _run_report(args)
    if args.command == "serve":
        from safescope.web import serve

        serve(args.host, args.port, trust_proxy=args.trust_proxy)
        return EXIT_OK
    parser.print_help()
    return EXIT_USAGE
