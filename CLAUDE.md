# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

A collection of Claude Code **skills**. Currently one skill: `skills/scan-android/` (an Android source/APK scanner). Skills are **markdown-orchestrated**:

- `skills/scan-android/SKILL.md` is the **single source of truth** for the scan workflow — Claude follows its numbered steps. Change behavior there, not by guessing.
- `skills/scan-android/agents/*.md` (`hunter.md`, `verifier.md`) are **subagent prompt templates** filled by the orchestrator (`{PLACEHOLDER}` substitution), then dispatched as subagents.
- `skills/scan-android/CONVENTIONS.md` defines the `findings.json` schema, `.scan/config.json`, dedup, severity, report rules.

## Scripts (`skills/scan-android/scripts/`)

- **Python standard library only.** The repo has no runtime dependencies of its own. Scan engines (semgrep, detekt, pmd, joern) are detected by default; installation to `~/.scan-android/` is allowed only when the caller explicitly passes `--install-missing`. Never add them as repo dependencies.
- Tests use the standard-library `unittest` runner. Validate scripts with both `unittest discover` and `py_compile`; real forward testing additionally runs the deterministic pipeline on an Android project.

## scan-android architecture facts (don't regress these)

- **Dimensionless:** every scan runs ALL rules. There is no `--checks` flag and no security/stability/perf selection — scope (`--diff`/`--module`/`--files`/`--full`) is the only scan parameter.
- **Stateless:** no ledger, no cross-scan state machine. `merge_findings.py` overwrites `findings.json` each run; reports show only the current scan (no commit/time, no first/last-seen).
- **Rules come from engines/community and pinned in-repo additions:** Semgrep registry is opt-in; `queries/` and `rules/ai/hunting.md` contain maintained Android gaps.
- Preflight is detection-only by default. Installation requires explicit `--install-missing`; missing optional engines make the final scan incomplete instead of aborting all retained results.

## Conventions

- Commit messages in **English**.
- **Do not make intermediate commits** — commit only when explicitly asked.
- Never commit a scanned project's `.scan/` outputs.

## Gotchas

- Top-level `docs/` is **gitignored** (design docs, not in the repo).
- `skills/scan-android/docs/install-engines.md` is force-tracked despite the `skills/scan-android/docs` ignore rule (README references it).
