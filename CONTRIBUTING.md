# Contributing

```bash
git clone https://github.com/pashvithareddy-debug/HashVault && cd HashVault
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Workflow: fork → branch → implement → test → lint → commit → pull request.

Before opening a PR, run:

```bash
ruff check . && ruff format --check .
mypy
pytest --cov
```

(Without dev tools installed, `python -m unittest discover -s tests -t .` with `PYTHONPATH=src` runs the suite.)

Guidelines: keep the runtime dependency-free; core services must not print or call `sys.exit`;
add tests for every behavior change (including failure paths); use conventional commit messages
(`feat:`, `fix:`, `test:`, `docs:`, `refactor:`, `ci:`).
