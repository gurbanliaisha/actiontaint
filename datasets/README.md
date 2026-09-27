# Datasets

This directory contains structured metadata for the evaluation artifacts included in this repository.

These files are not new experimental results. They are inventory files built from the reports, JSON outputs, and benchmark metadata already present in the artifact.

## Files

- `benchmarks.json`  
  Inventory of the synthetic and complex benchmark suites.

- `real-projects.json`  
  Inventory of real open-source evaluation targets, including upstream repositories and the scan targets used during evaluation.

- `seeded-configs.json`  
  Inventory of the seeded vulnerability experiments, including seeded files and before/after metrics.

- `evaluation-sets.json`  
  High-level map of the evaluation campaigns and their primary artifact paths.

## Conventions

- `artifact_path` and `artifact_paths` values are relative to the root of this GitHub artifact repository.
- `scan_targets_during_evaluation` values describe the original target paths used during evaluation in the local workspace where the scans were run.
- `upstream_repository` values use `owner/repo` format when the upstream remote was recoverable from the original clones.
- `project_id` and `evaluation_set` identifiers are stable local names used across these dataset files.

## Scope

These dataset files are intended to support:

- paper artifact navigation,
- reproducibility notes,
- evaluation indexing,
- structured summaries of what was analyzed.

They are not a substitute for the primary evidence under `evaluations/`.
