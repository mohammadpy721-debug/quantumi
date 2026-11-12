<h1 align="center">QuantumAI</h1>
<p align="center"><strong>Audit Python repositories with AST analysis and OpenAI, then generate the README.</strong></p>

<p align="center">
  <img alt="Python 3.9+" src="https://img.shields.io/badge/python-3.9%2B-blue">
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="Status: alpha" src="https://img.shields.io/badge/status-alpha-orange">
</p>

QuantumAI parses your project with Python's built-in `ast` module, flags risky patterns locally, and
sends **structured metadata** (never whole files) to OpenAI for a deeper security and performance
review. The same project summary can then be turned into a complete, professional `README.md`.

```text
$ quantumai audit ./shop-api
Parsed 42 files, 187 functions, 23 classes
high    app/db.py:58      SQL query built from a string
high    app/config.py:4   Hardcoded secret in 'SECRET_KEY'
medium  app/jobs.py:102   subprocess call with shell=True
5 findings: 2 high, 2 medium, 1 low
```

*(Illustrative output. Results depend on your code.)*

## Features

- **Local AST scan.** Extracts classes, functions, imports and approximate cyclomatic complexity from every `.py` file.
- **Built-in security rules.** Detects `eval`/`exec`, unsafe `pickle`/`marshal`/`yaml.load`, SQL built from strings, `shell=True`, `os.system`, disabled TLS verification, weak hashes (MD5/SHA-1), `tempfile.mktemp`, `debug=True`, bare `except`, and hardcoded secrets.
- **AI review.** `gpt-4o-mini` (configurable) confirms findings, explains impact, proposes fixes, and looks for risks the local rules cannot see.
- **README generation.** Produces an English README from real modules, functions and packaging files.
- **CI friendly.** JSON reports, `--fail-on <severity>` exit codes, and a fully offline `--no-ai` mode.
- **Rich terminal output.** Progress bars, severity-colored tables and focused detail panels.

## Installation

```bash
pip install quantumai
```

From source:

```bash
git clone https://github.com/your-username/quantumai.git
cd quantumai
pip install -e ".[dev]"
```

Set your OpenAI API key (not needed with `--no-ai`):

```bash
export OPENAI_API_KEY="sk-..."
```

## Quick start

```bash
quantumai audit .                    # audit the current directory
quantumai audit ./src --no-ai        # local rules only, nothing leaves your machine
quantumai audit . -x tests -x docs   # skip directories by name
quantumai audit . -o report.json     # save the full report
quantumai audit . --fail-on high     # exit 1 if any high or critical finding exists
quantumai readme .                   # write ./README.md (refuses to overwrite without --force)
```

### `quantumai audit [PATH]`

| Option | Default | Description |
| --- | --- | --- |
| `-m, --model` | `gpt-4o-mini` | OpenAI model used for the review |
| `--no-ai` | off | Static analysis only |
| `-x, --exclude DIR` | none | Directory name to skip; repeatable |
| `-o, --output FILE` | none | Write the full JSON report |
| `--fail-on LEVEL` | `none` | `info`, `low`, `medium`, `high` or `critical`; exit status 1 at or above it |

### `quantumai readme [PATH]`

| Option | Default | Description |
| --- | --- | --- |
| `-m, --model` | `gpt-4o-mini` | OpenAI model used for writing |
| `-o, --output FILE` | `PATH/README.md` | Where to save the README |
| `--notes TEXT` | none | Extra guidance, e.g. `"emphasize the REST API"` |
| `--force` | off | Overwrite an existing file |

Exit codes: `0` success, `1` findings at or above `--fail-on`, `2` error (bad key, network failure, invalid path).

## Python API

```python
from quantumai import CodeAnalyzer, ReadmeGenerator

analyzer = CodeAnalyzer("./my-project", model="gpt-4o-mini")
modules = analyzer.scan()

report = analyzer.audit(modules)              # use_ai=False for offline mode
for finding in report.findings:
    print(finding.severity, finding.file, finding.line, finding.title)

summary = analyzer.summarize(modules)
ReadmeGenerator(model="gpt-4o-mini").write(summary, "README.generated.md")
```

## What is sent to OpenAI

| Sent | Never sent |
| --- | --- |
| File paths and import names | Full source files or function bodies |
| Class/function names, argument names, complexity | The line containing a hardcoded secret |
| Static findings with one trimmed flagged line each | Your API key |

Use `--no-ai` for a fully offline audit. Review your organization's policy before auditing proprietary code with any third-party API.

## How it works

```text
 .py files ──► ast.parse ──► metadata + local rules ──► findings
                                   │                        │
                                   ▼                        ▼
                         batched JSON to OpenAI ──► merged, deduplicated report
                                   │
                                   └──► project summary ──► README.md
```

## Project structure

```text
quantumai/
├── pyproject.toml
├── README.md
├── src/quantumai/
│   ├── __init__.py   public API and version
│   ├── core.py       CodeAnalyzer, AST visitor, OpenAI audit
│   ├── readme.py     ReadmeGenerator
│   └── cli.py        click + rich command-line interface
└── web/
    └── index.html    single-page project site (Tailwind CSS)
```

## Use in CI

```yaml
# .github/workflows/audit.yml
name: QuantumAI audit
on: [pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install quantumai
      - run: quantumai audit . --fail-on high -o report.json
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

## Limitations

- Static rules are pattern-based and can produce false positives or miss issues; treat results as a review aid, not a guarantee.
- The AI review sees metadata, not logic, so its findings are leads to verify.
- Files over 500 KB and files that fail to parse are skipped and listed as warnings.

## Contributing

Issues and pull requests are welcome.

```bash
pip install -e ".[dev]"
ruff check src
pytest
```

## License

MIT. Add a `LICENSE` file with your name before publishing.
