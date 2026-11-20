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
5. Add every new finding ID to [docs/checks.md](docs/checks.md) (a test enforces it)
   and, for a new check family, a row to the *What it checks* table in the README.

## Branches and workflow

| Branch | Purpose |
|---|---|
| `main` | Released, deployed code. Vercel deploys every push to `main`. |
| `dev` | Integration branch. CI runs on every push; changes reach `main` only when CI is green. |
| `feat/*`, `fix/*`, `docs/*`, `test/*` | One change each, opened as a PR against `dev`. |
| `security/*` | Security fixes. Do not describe an unfixed vulnerability publicly; see [SECURITY.md](SECURITY.md). |

The steps for every change:

1. Open (or pick) an issue that describes the problem.
2. Branch from `dev` and write a test that shows the expected behaviour first.
3. Make the smallest change that passes it. Do not mix refactors with fixes.
4. Run `ruff check .`, `ruff format --check .`, `mypy` and `pytest`.
5. Read your own diff: no secrets, no unrelated changes, no error messages that leak data.
6. Open the PR, link the issue, explain risks and tests, wait for green CI.

## Pull requests

1. Fork and create a branch: `git checkout -b feat/mixed-content-check dev`.
2. Use [Conventional Commits](https://www.conventionalcommits.org/) for messages,
   e.g. `feat(headers): flag CSP without object-src`.
3. Add an entry under **Unreleased** in `CHANGELOG.md`.
4. Open the PR against `dev` and fill in the template. CI must be green
   (lint, format, mypy, tests on Linux/Windows/macOS with an 85% coverage gate,
   wheel install and the GitHub Action self-test).

## Reporting bugs

Open an issue with the command you ran, what you expected and what happened. Please do not
include URLs of sites that are not yours.
