# CLI Reference

```bash
python -m actiontaint <command> [options]    # or: actiontaint <command> [options]
python -m actiontaint <command> -h           # built-in help
```

| Command | Purpose | Needs CodeQL |
|---|---|---|
| [`scan`](#scan) | analyze one Next.js project | yes |
| [`eval`](#eval) | run a benchmark suite and score the results | yes |
| [`convert-semgrep`](#convert-semgrep) | convert a Semgrep JSON report into ActionTaint's report shape | no |
| [`compare`](#compare) | side-by-side counts for ActionTaint, Semgrep, and CodeQL reports | no |

CodeQL is found through `ACTIONTAINT_CODEQL` (full path to the executable) or `codeql` on `PATH`.

---

## scan

```bash
python -m actiontaint scan [target] [options]
```

| Option | Values | Default | Description |
|---|---|---|---|
| `target` | directory | `.` | project to analyze |
| `--format` | `cli`, `json`, `sarif`, `csv`, `html` | `cli` | report format |
| `--output` | file | stdout | write the report to a file |
| `--model-dir` | directory | `<target>/.actiontaint/` | where the generated pack, CodeQL database, and SARIF go |
| `--parser` | `auto`, `typescript`, `regex` | `auto` | `auto` uses the TypeScript parser and falls back to regex if Node or TypeScript is missing |
| `--backend` | `codeql` | `codeql` | taint engine (only CodeQL is supported) |

### What a scan does

1. collects `.ts/.tsx/.js/.jsx` files (skipping `node_modules`, `.next`, `dist`, `build`, ...)
2. finds Server Actions and the client call sites that make them reachable
3. writes a CodeQL pack to `<model-dir>/codeql-pack/`, including `models/actiontaint-sources.json` (the boundary model)
4. runs `codeql database create` (always fresh), `codeql pack install`, and `codeql database analyze`
5. renders the report

### Report formats

| Format | Contents |
|---|---|
| `cli` | summary counts, warnings/errors, and each finding with source, sink line, and taint path |
| `json` | everything: project info, Server Actions, boundary models, findings, warnings, errors (paths relative, no function bodies) |
| `sarif` | SARIF 2.1.0, one rule per vulnerability type (`actiontaint/sql-injection`, `actiontaint/ssrf`, `actiontaint/open-redirect`, `actiontaint/path-traversal`, `actiontaint/command-injection`, `actiontaint/idor`) with code flows; ready for GitHub code scanning |
| `csv` | one row per finding |
| `html` | a simple standalone page |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | analysis completed, no findings |
| `1` | analysis completed, at least one finding |
| `2` | analysis did not complete: target missing, CodeQL not found, or `database create` / `pack install` / `analyze` failed. The reason is printed on stderr and listed under `errors` in the report. |

In CI, treat both `1` and `2` as a failed check.

---

## eval

```bash
python -m actiontaint eval [benchmarks] [options]
```

| Option | Values | Default | Description |
|---|---|---|---|
| `benchmarks` | directory | `benchmarks` | a suite (`benchmarks/synthetic`), or a folder of suites (runs all of them) |
| `--tools` | comma list of `actiontaint`, `codeql`, `semgrep` | all three | tools to run on each benchmark |
| `--format` | `table`, `json` | `table` | output format |
| `--output` | file | stdout | write the evaluation to a file |

- **Benchmarks:** each benchmark is a directory with an `expected.json` that lists the expected findings as `type` + `source_function`.
- **Baselines:**
  - `codeql`: `codeql/javascript-queries@2.3.9:codeql-suites/javascript-security-extended.qls`
  - `semgrep`: `semgrep --config=p/default`, which needs network access
- **Output columns:** `findings`, `tp` (true positives), `fp` (false positives), `missed`, `runtime`, `status`.
- **Scoring:**
  - An ActionTaint finding is a TP when both its type and its source function match.
  - A baseline finding is a TP when its CodeQL rule or Semgrep CWE maps to the expected type.
  - Anything else is an FP.
- **Files:** everything goes to `<suite>/.actiontaint-eval/<benchmark>/`. The benchmark folders themselves are not modified.

---

## convert-semgrep

```bash
python -m actiontaint convert-semgrep <semgrep.json> [--repo-name NAME] [--format json|cli|csv] [--output FILE]
```

This only reformats Semgrep's output; it does not reconstruct Server Action semantics. `--repo-name` overrides the project name inferred from the scanned paths.

---

## compare

```bash
# one project
python -m actiontaint compare --actiontaint at.json --semgrep semgrep.json --codeql codeql.sarif

# a folder of <repo>-actiontaint.json, <repo>-semgrep.json, <repo>-codeql.sarif files
python -m actiontaint compare --results-dir evaluations/static-analyzer-comparison [--repos a,b]
```

| Option | Description |
|---|---|
| `--actiontaint`, `--semgrep`, `--codeql` | report files for single-project mode (each is optional) |
| `--results-dir` | folder mode; repositories are inferred from `*-actiontaint.json` |
| `--repos` | limit folder mode to these repositories |
| `--format` | `table` (default), `json`, `csv` |
| `--output` | write to a file |

Each row shows files, Server Actions, reachable actions, and finding counts per tool, plus a one-line interpretation. The counts are a triage aid, not proof that the tools found the same issues.
