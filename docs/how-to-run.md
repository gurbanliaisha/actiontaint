# How to Run

## 1. Install

| Requirement | Why | Tested version |
|---|---|---|
| Python 3.10+ | the tool | 3.10–3.14 |
| Node.js + `npm ci` | TypeScript compiler used by the AST parser | Node 22, TypeScript 5.9.3 |
| CodeQL CLI | taint tracking | 2.25.4 |

```bash
python -m pip install -e .
npm ci
```

Without `npm ci`, ActionTaint falls back to a less precise regex parser and prints a warning. It also finds TypeScript in the scanned project's own `node_modules`.

Point ActionTaint at CodeQL if `codeql` is not on your `PATH`:

```bash
export ACTIONTAINT_CODEQL=/path/to/codeql/codeql            # Linux / macOS
$env:ACTIONTAINT_CODEQL = 'C:\path\to\codeql\codeql.exe'     # Windows PowerShell
```

The generated query pack depends on `codeql/javascript-all` 2.7.0, and the default-CodeQL baseline uses `codeql/javascript-queries` 2.3.9. Both are downloaded automatically the first time, so the first run needs network access.

## 2. Scan a project

```bash
python -m actiontaint scan /path/to/next-app
```

Useful options:

```bash
# machine-readable report, generated files kept outside the scanned project
python -m actiontaint scan /path/to/next-app --format json --output report.json --model-dir /tmp/at-model

# SARIF for GitHub code scanning
python -m actiontaint scan /path/to/next-app --format sarif --output actiontaint.sarif
```

Without `--model-dir`, generated files go to `<project>/.actiontaint/`. The CodeQL database is rebuilt on every scan, so results always match the current code. See [cli-reference.md](cli-reference.md) for all options and [exit codes](cli-reference.md#exit-codes).

## 3. Reproduce the benchmark results

```bash
python -m actiontaint eval benchmarks/synthetic --tools actiontaint,codeql --format json --output synthetic-eval.json
python -m actiontaint eval benchmarks/complex   --tools actiontaint,codeql --format json --output complex-eval.json
```

- `--tools actiontaint` alone skips the default-CodeQL baseline and halves the runtime.
- Add `semgrep` to `--tools` for a Semgrep `p/default` baseline, which needs network access.
- Each benchmark takes about 1 minute for ActionTaint and 1.5 minutes for default CodeQL.
- All intermediate files go to `benchmarks/<suite>/.actiontaint-eval/<benchmark>/`, which is gitignored:
  - `actiontaint.json`: the full ActionTaint report
  - `default-codeql.sarif`: the baseline result
  - the CodeQL databases

Compare the output with the archived results in [`evaluations/`](../evaluations/) and [evaluation-summary.md](evaluation-summary.md).

### Default CodeQL baseline by hand

```bash
codeql database create db --language=javascript-typescript --source-root=benchmarks/synthetic/formdata_fetch_ssrf --overwrite
codeql database analyze db codeql/javascript-queries@2.3.9:codeql-suites/javascript-security-extended.qls \
  --download --format=sarif-latest --output=default-codeql.sarif
```

## 4. Real-world and seeded experiments

The upstream projects are not bundled. [`datasets/real-projects.json`](../datasets/real-projects.json) lists their repositories, and [`datasets/seeded-configs.json`](../datasets/seeded-configs.json) lists the files inserted for each seeded experiment. To re-run one:

1. clone the project and scan it with ActionTaint and with default CodeQL (baseline),
2. add the seeded files and scan both again (seeded),
3. compare the before/after counts with the archived report.

## 5. Compare with Semgrep

```bash
python -m actiontaint convert-semgrep semgrep.json --output semgrep-normalized.json
python -m actiontaint compare --results-dir evaluations/static-analyzer-comparison
```

## 6. Run the tests

```bash
python -m pip install -e ".[test]"
python -m pytest
```

- **Unit tests (seconds, no CodeQL):** framework reconstruction for all 18 benchmarks with both parsers, query generation, CLI exit codes, report formats, and evaluation scoring.
- **`tests/test_codeql_integration.py`:** runs the full pipeline on `tests/fixtures/regression_app`, which has 10 vulnerable and 7 safe or unreachable actions. It is skipped automatically when CodeQL is not available.

## Cleaning up

Everything a run creates is covered by `.gitignore`: `.actiontaint/`, `.actiontaint-eval/`, and `outputs/`. Delete those folders to return to a clean checkout.
