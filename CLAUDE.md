# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

A collection of Claude Code **skills**. Currently one skill: `skills/scan-android/` (an Android source/APK scanner). Skills are **markdown-orchestrated**:

- `skills/scan-android/SKILL.md` is the **single source of truth** for the scan workflow — Claude follows its numbered steps. Change behavior there, not by guessing.
- `skills/scan-android/agents/*.md` (`hunter.md`, `verifier.md`) are **subagent prompt templates** filled by the orchestrator (`{PLACEHOLDER}` substitution), then dispatched as subagents.
- `skills/scan-android/CONVENTIONS.md` defines the `findings.json` schema, `.scan/config.json`, dedup, severity, report rules.

## Scripts (`skills/scan-android/scripts/`)

- **Python standard library only.** The repo has no dependencies of its own. Scan engines (semgrep, detekt, pmd, joern) are auto-installed at runtime to `~/.scan-android/` (venv + tools) by `scripts/tools/installer.py` — never add them as repo deps.
- **No test framework.** Validate edits with `python3 -m py_compile <file>` (or ast-parse). Real end-to-end testing = run the skill on an actual Android project (e.g. via `preflight.py` → `run_engines.py` → subagents → `merge_findings.py` → `render_report.py`).

## scan-android architecture facts (don't regress these)

- **Dimensionless:** every scan runs ALL rules. There is no `--checks` flag and no security/stability/perf selection — scope (`--diff`/`--module`/`--files`/`--full`) is the only scan parameter.
- **Stateless:** no ledger, no cross-scan state machine. `merge_findings.py` overwrites `findings.json` each run; reports show only the current scan (no commit/time, no first/last-seen).
- **Rules come from engines/community,** not in-repo: Semgrep loads community registry packs + `queries/semgrep/android.yaml`; the only hand-maintained rule files are `queries/` and `rules/ai/hunting.md` (AI-branch hunting heuristics, neutral `R-AI-NNN` ids).
- Strict preflight: required engines auto-install or the scan aborts (no degraded mode).

## Conventions

- Commit messages in **English**.
- **Do not make intermediate commits** — commit only when explicitly asked.
- Never commit a scanned project's `.scan/` outputs.

## Gotchas

- Top-level `docs/` is **gitignored** (design docs, not in the repo).
- `skills/scan-android/docs/install-engines.md` is force-tracked despite the `skills/scan-android/docs` ignore rule (README references it).
