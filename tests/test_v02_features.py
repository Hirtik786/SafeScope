"""v0.2 features: several targets, SARIF output, re-rendering saved reports."""

from __future__ import annotations

import http.server
import json
import sys
import threading
from pathlib import Path

import pytest

from safescope.cli import main
from safescope.models import ScanResult

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "examples"))
from vulnerable_demo_server import make_handler  # noqa: E402


@pytest.fixture
def demo_servers():
    """One insecure and one well-configured demo server."""
    servers = [
        http.server.ThreadingHTTPServer(("127.0.0.1", 0), make_handler(fixed=False)),
        http.server.ThreadingHTTPServer(("127.0.0.1", 0), make_handler(fixed=True)),
    ]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    yield [f"http://127.0.0.1:{s.server_address[1]}/" for s in servers]
    for server in servers:
        server.shutdown()
        server.server_close()


def run(argv, capsys):
    code = main(argv)
    out = capsys.readouterr()
    return code, out.out, out.err


# --- several targets -----------------------------------------------------------


def test_two_targets_json_is_one_valid_document_in_input_order(demo_servers, capsys):
    bad, good = demo_servers
    code, out, _ = run(["scan", bad, good, "--skip", "tls,transport", "-f", "json", "-q"], capsys)
    data = json.loads(out)
    assert code == 0
    assert data["schema_version"] == 1
    assert [r["target"] for r in data["results"]] == [bad, good]
    assert data["results"][0]["grade"] != data["results"][1]["grade"]


def test_targets_file_with_comments(demo_servers, tmp_path, capsys):
    bad, good = demo_servers
    listing = tmp_path / "sites.txt"
    listing.write_text(f"# staging sites\n{bad}\n\n{good}  # the fixed one\n", encoding="utf-8")
    code, out, _ = run(
        ["scan", "--targets-file", str(listing), "--skip", "tls,transport", "-f", "json", "-q"],
        capsys,
    )
    assert code == 0
    assert len(json.loads(out)["results"]) == 2


def test_fail_on_considers_every_target(demo_servers, capsys):
    bad, good = demo_servers
    code, _, _ = run(["scan", good, bad, "--skip", "tls,transport", "--fail-on", "medium", "-q"], capsys)
    assert code == 1


def test_one_unreachable_target_is_reported_and_exits_3(demo_servers, capsys):
    _, good = demo_servers
    code, out, err = run(["scan", good, "http://127.0.0.1:9/", "--skip", "tls,transport", "-f", "json", "-q"], capsys)
    assert code == 3
    assert "could not reach http://127.0.0.1:9/" in err
    assert json.loads(out)["target"] == good  # the reachable one is still reported


@pytest.mark.parametrize(
    "argv",
    [
        ["scan"],
        ["scan", "a.example", "b.example", "-f", "html"],
        ["scan", "a.example", "--concurrency", "0"],
        ["scan", "a.example", "--concurrency", "99"],
        ["scan", "--targets-file", "/does/not/exist.txt"],
    ],
)
def test_usage_errors(argv, capsys):
    code, _, err = run(argv, capsys)
    assert code == 2
    assert "error" in err


class Slow(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        import time

        time.sleep(3)
        self.send_response(200)
        self.end_headers()


def test_max_time_budget_stops_a_slow_target(capsys):
    import time

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Slow)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        started = time.monotonic()
        code, _, err = run(
            ["scan", f"http://127.0.0.1:{server.server_address[1]}/", "--max-time", "0.5", "--timeout", "5", "-q"],
            capsys,
        )
        elapsed = time.monotonic() - started
    finally:
        server.shutdown()
        server.server_close()
    assert code == 3
    assert "timed out" in err or "budget" in err
    assert elapsed < 2.5  # the 5 s per-request timeout was capped by the 0.5 s budget


# --- SARIF -----------------------------------------------------------------------


def test_sarif_structure(demo_servers, capsys):
    bad, good = demo_servers
    code, out, _ = run(["scan", bad, good, "--skip", "tls,transport", "-f", "sarif", "-q"], capsys)
    log = json.loads(out)
    assert log["version"] == "2.1.0"
    assert len(log["runs"]) == 2
    bad_run, good_run = log["runs"]
    assert good_run["results"] == []
    rules = {r["id"]: r for r in bad_run["tool"]["driver"]["rules"]}
    assert bad_run["results"], "the insecure demo must produce results"
    for res in bad_run["results"]:
        assert res["ruleId"] in rules
        assert bad_run["tool"]["driver"]["rules"][res["ruleIndex"]]["id"] == res["ruleId"]
        assert res["level"] in ("error", "warning", "note")
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("http")
    assert all(0.0 <= float(r["properties"]["security-severity"]) <= 10.0 for r in rules.values())
    assert rules["disclosure.cors.wildcard_credentials"]["properties"]["security-severity"] == "5.0"


# --- saved reports -----------------------------------------------------------------


def test_report_command_rerenders_saved_json(demo_servers, tmp_path, capsys):
    bad, _ = demo_servers
    saved = tmp_path / "scan.json"
    assert main(["scan", bad, "--skip", "tls,transport", "-f", "json", "-o", str(saved), "-q"]) == 0
    html = tmp_path / "report.html"
    assert main(["report", str(saved), "-f", "html", "-o", str(html)]) == 0
    original = ScanResult.from_dict(json.loads(saved.read_text()))
    assert original.grade in html.read_text()
    capsys.readouterr()
    code, out, _ = run(["report", str(saved), "-f", "json"], capsys)
    assert json.loads(out) == json.loads(saved.read_text())  # lossless round trip


def test_report_command_handles_multi_target_files(demo_servers, tmp_path, capsys):
    saved = tmp_path / "many.json"
    assert main(["scan", *demo_servers, "--skip", "tls,transport", "-f", "json", "-o", str(saved), "-q"]) == 0
    capsys.readouterr()
    code, out, _ = run(["report", str(saved), "-f", "markdown"], capsys)
    assert code == 0
    assert out.count("## SafeScope report for") == 2


@pytest.mark.parametrize(
    "content, message",
    [
        ("not json", "Expecting value"),
        ('{"hello": 1}', "not a SafeScope JSON report"),
        ('{"tool": {"name": "SafeScope"}, "schema_version": 99}', "unsupported report schema_version"),
        ('{"tool": {"name": "SafeScope"}, "schema_version": 1}', "invalid SafeScope report"),
    ],
)
def test_report_command_rejects_bad_files(tmp_path, capsys, content, message):
    bad = tmp_path / "bad.json"
    bad.write_text(content, encoding="utf-8")
    code, _, err = run(["report", str(bad)], capsys)
    assert code == 2
    assert message in err
