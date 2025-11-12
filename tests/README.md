# CloakMCP Test Suite

Comprehensive test suite for CloakMCP v0.3.1.

## Test Files

- **`test_smoke.py`**: Basic smoke test (original)
- **`test_comprehensive.py`**: Full feature coverage (300+ tests)
- **`test_api.py`**: FastAPI server endpoint tests

## Running Tests

### Prerequisites

```bash
# Install test dependencies
pip install pytest pytest-cov fastapi httpx

# Ensure CloakMCP is installed
pip install -e .

# Generate test keys
mkdir -p keys
openssl rand -hex 32 > keys/mcp_hmac_key
```

### Run All Tests

```bash
pytest -v
```

### Run Specific Test File

```bash
pytest -v tests/test_comprehensive.py
pytest -v tests/test_api.py
```

### Run with Coverage

```bash
pytest --cov=cloak --cov-report=html --cov-report=term
```

Coverage report will be generated in `htmlcov/index.html`.

### Run Specific Test Class

```bash
pytest -v tests/test_comprehensive.py::TestScanner
pytest -v tests/test_comprehensive.py::TestVault
```

### Run Specific Test Function

```bash
pytest -v tests/test_comprehensive.py::TestScanner::test_scan_email
```

### Run Tests in Parallel (with pytest-xdist)

```bash
pip install pytest-xdist
pytest -n auto  # Use all CPU cores
```

## Test Organization

### `test_comprehensive.py` Structure

```
├── Fixtures
│   ├── temp_dir: Temporary directory for tests
│   ├── policy_yaml: Test policy YAML file
│   └── policy: Loaded Policy object
├── TestNormalizer: Unicode, line endings, zero-width chars
├── TestScanner: Regex, entropy, IP, URL detectors
├── TestActions: Redact, pseudonymize, block, hash, templates
├── TestPolicy: YAML loading, CIDR, email whitelisting
├── TestVault: Encryption, deterministic tagging, persistence
├── TestDirPack: .mcpignore, pack/unpack, file iteration
├── TestCLI: sanitize_text, dry-run, blocking
├── TestAudit: Event logging, JSONL format
├── TestUtils: Hashing, base62, Unicode normalization
├── TestEdgeCases: Empty input, long input, malformed data
├── TestErrorHandling: Missing files, invalid YAML, bad keys
├── TestIntegration: Full workflow tests
└── TestPerformance: Large file scanning, many secrets
```

### `test_api.py` Structure

```
├── Fixtures
│   ├── setup_api_token: Mock API token
│   ├── policy_yaml: Test policy
│   └── client: FastAPI TestClient
├── TestAPIAuthentication: Bearer token validation
├── TestAPISanitize: /sanitize endpoint tests
├── TestAPIScan: /scan endpoint tests
└── TestAPIErrors: Error handling, invalid inputs
```

## Test Coverage Goals

| Module            | Current | Target |
| ----------------- | ------- | ------ |
| `actions.py`      | ~80%    | 95%    |
| `audit.py`        | ~90%    | 95%    |
| `cli.py`          | ~60%    | 90%    |
| `dirpack.py`      | ~70%    | 90%    |
| `normalizer.py`   | ~95%    | 100%   |
| `policy.py`       | ~75%    | 90%    |
| `scanner.py`      | ~85%    | 95%    |
| `server.py`       | ~70%    | 90%    |
| `storage.py`      | ~80%    | 95%    |
| `utils.py`        | ~90%    | 100%   |
| **Overall**       | ~75%    | 95%    |

## Continuous Integration

Example `.github/workflows/test.yml`:

```yaml
name: Test CloakMCP

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ['3.10', '3.11', '3.12']

    steps:
      - uses: actions/checkout@v3

      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v4
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install dependencies
        run: |
          pip install -e .
          pip install pytest pytest-cov

      - name: Generate test keys
        run: |
          mkdir -p keys
          openssl rand -hex 32 > keys/mcp_hmac_key

      - name: Run tests
        run: pytest --cov=cloak --cov-report=xml

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.xml
```

## Writing New Tests

### Template for New Test

```python
import pytest
from cloak.your_module import your_function

class TestYourFeature:
    def test_basic_functionality(self):
        """Test basic case"""
        result = your_function("input")
        assert result == "expected_output"

    def test_edge_case(self):
        """Test edge case"""
        result = your_function("")
        assert result == ""

    def test_error_handling(self):
        """Test error handling"""
        with pytest.raises(ValueError):
            your_function(None)
```

### Best Practices

1. **Use fixtures**: Avoid code duplication
2. **Test edge cases**: Empty, None, very large inputs
3. **Test errors**: Ensure proper exception handling
4. **Use assertions**: Clear, specific assertions
5. **Docstrings**: Explain what each test validates
6. **Isolate tests**: Each test should be independent
7. **Clean up**: Use fixtures with proper teardown

## Troubleshooting

### "FileNotFoundError: mcp_policy.yaml"

**Solution**: Tests change directory to `temp_dir`. Ensure fixtures set up policy files correctly.

### "ModuleNotFoundError: No module named 'cloak'"

**Solution**: Install package in editable mode:

```bash
pip install -e .
```

### "PermissionError: ~/.cloakmcp/"

**Solution**: Ensure test fixtures use `tmp_path` for vaults, not home directory.

### API tests failing with "RuntimeError: Missing API token"

**Solution**: `test_api.py` uses `setup_api_token` fixture. Ensure it runs before tests.

## Test Maintenance

- **Review coverage**: Run `pytest --cov` monthly
- **Update tests**: When adding features, add corresponding tests
- **Fix flaky tests**: Ensure tests are deterministic
- **Profile slow tests**: Use `pytest --durations=10` to find slow tests

## Additional Resources

- **pytest docs**: https://docs.pytest.org/
- **Coverage.py**: https://coverage.readthedocs.io/
- **FastAPI testing**: https://fastapi.tiangolo.com/tutorial/testing/

---

*Test suite maintained by Olivier Vitrac — Adservio Innovation Lab*
