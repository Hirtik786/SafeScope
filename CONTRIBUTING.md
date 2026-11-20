# Contributing to SafeScope

Thanks for helping make the web a little safer! Every contribution counts — a typo fix, a bug
report, a new check or better docs.

## Ground rules

- **Passive checks only.** SafeScope must stay safe to run against production. No attack
  payloads, fuzzing, brute force, or anything a normal browser wouldn't do.
- **No runtime dependencies.** The package uses only the Python standard library.
  Dev tools (pytest, ruff, mypy) are fine.
- Be kind. See the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

```bash
git clone https://github.com/Karim-Bazooka/SafeScope.git
cd SafeScope
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Run the same checks as CI:

```bash
pytest                 # tests (no internet needed: they use local servers)
ruff check . && ruff format --check .
mypy                   # strict type checking
```

Try your change against the demo server:

```bash
python examples/vulnerable_demo_server.py &
safescope scan http://127.0.0.1:8000 --skip tls
```

## Adding a new check

The most valuable contributions are new checks. Follow [docs/writing-checks.md](docs/writing-checks.md);
in short:

1. Create `src/safescope/checks/<name>.py` with a `Check` subclass.
2. Keep network access in `run()` and the logic in a pure `analyze()` method.
3. Register it in `src/safescope/checks/__init__.py`.
4. Add tests in `tests/` using the `make_ctx` fixture (no real network).
5. Add a row to the *What it checks* table in the README.

## Pull requests

1. Fork and create a branch: `git checkout -b feat/mixed-content-check`.
2. Use [Conventional Commits](https://www.conventionalcommits.org/) for messages,
   e.g. `feat(headers): flag CSP without object-src`.
3. Add an entry under **Unreleased** in `CHANGELOG.md`.
4. Open the PR and fill in the template. CI must be green.

## Reporting bugs

Open an issue with the command you ran, what you expected and what happened. Please do not
include URLs of sites that are not yours.
