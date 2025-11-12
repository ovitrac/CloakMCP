# Contributing

- Contributions are MIT-licensed.
- Never include real secrets in issues/PRs/tests.

## Dev setup
```bash
python -m venv .venv && . .venv/bin/activate
pip install -e .
pip install pytest mypy black isort
```

## Tests & style
```bash
pytest -q
mypy cloak
black --check . && isort --check-only .
```
