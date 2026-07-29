# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

`scan-android` is a stateless Android/APK code scanner packaged as a Claude Code skill. The entry point and workflow are in `SKILL.md`; schema/dedup/report details are in `CONVENTIONS.md`. Read those before changing behavior.

## Hard invariants

- **Orchestration scripts are Python standard-library only.** Two third-party dependencies are allowed, each in its **own isolated venv**, never imported by the orchestration scripts: `semgrep` (`~/.scan-android/venv/`) and the tree-sitter precision tier `tree-sitter` + `tree-sitter-language-pack` (`~/.scan-android/repomap-venv/`, used by `repo_map.py`, which re-execs into that venv or falls back to stdlib `source_nav.py`). Do **not** add `requests`, `pyyaml`, `lxml`, etc. to any orchestration script under `scripts/` — parse with stdlib (`json`, `xml.etree`, `urllib`). Both venvs are auto-installed and non-blocking: a bare machine still runs (semgrep blocks only if not excluded; tree-sitter degrades to source-nav).
- **The skill is read-only.** It never modifies the scanned project's source. Only write under the scanned repo's `.scan/` (findings, reports, tmp, cache).
- **v3 is stateless.** No ledger, no `first_seen`/`last_seen`, no cross-scan reopen/close. `merge_findings.py` overwrites `.scan/findings.json` every run. Don't reintroduce historical state.
- **False-positive discipline.** When verification is uncertain, discard the candidate. User trust outweighs recall.

## Two-root model (don't confuse them)

Scripts run against **two independent roots**:

- **`<SKILL_DIR>`** = this skill's install dir (where `SKILL.md`/`scripts/`/`rules/` live). It can sit at any path (often symlinked, not necessarily under `.claude/skills/`). Scripts locate their own resources via `Path(__file__)` — **never hardcode `.claude/skills/...`** and don't rely on cwd to find `rules/` or `lib_scan.py`.
- **Scanned repo root** = the cwd when scripts run. `--repo-root` defaults to `.`; all `.scan/...` artifacts are relative to here.

When invoking scripts in docs/workflow, write `python3 <SKILL_DIR>/scripts/X.py` and let the caller substitute the real path. Shell env vars don't persist between Bash calls, so inline the path per command rather than `export`-ing once.

## Engine set (current)

`semgrep` (breadth, incl. taint), `detekt` (Kotlin), `pmd` (Java), `lint` (Android, via `./gradlew`), plus tree-sitter for both the hunter's **RepoMap** (cross-file code map) and verification-time call/type navigation via `nav_tools.py`. **Navigation backend is selected by `.scan/config.json` `nav_backend` (or env `SCAN_ANDROID_NAV_BACKEND`); default `auto`:**
- **`repo_map.py` (tree-sitter, the single precision tier) is the default.** Parses Java/Kotlin with tree-sitter tags queries (`scripts/tags/{java,kotlin}-tags.scm`; **we ship our own kotlin-tags — Aider has none — so Kotlin is not a blind spot**). AST-precise def/ref (no matches inside comments/strings, correct enclosing scope). Does **not** resolve overloads/receiver types — common-name disambiguation (`init`/`d`) is still name-level and closed by the verifier's per-hop Read (same as source-nav). Benchmarked (`nav_benchmark.py`) **on par with source-nav on nav precision** — its reason for being default is the RepoMap capability source-nav cannot produce (signature skeletons + PageRank + cross-file relations, fed to the hunter). Installed via pip into an isolated venv `~/.scan-android/repomap-venv/` (mirrors semgrep). Non-blocking: if the venv can't be built, nav falls back to source-nav.
- **`source_nav.py` (stdlib-only regex nav) is the fallback**, used only when tree-sitter is unavailable. Recall complete, precision name-collision-driven. Guarantees nav works on a bare/offline machine. **When nav_tools falls back to it, it prints an explicit `[WARN] nav-degraded`** so the operator knows precision dropped and should fix the repomap venv.

Never let tree-sitter's unavailability block a scan — it falls back to source-nav (with a warning). **`joern`, `scip-java`, and `stack-graphs` were all removed** (joern: `.kt` blind spot + 2GB + build requirement; scip-java: needs semanticdb that Gradle toolchain-forked javac rarely emits; stack-graphs: benchmark-rejected). tree-sitter is now the **single precision tier**, serving both hunter and verifier with no Kotlin blind spot — see memory `project-nav-backend-benchmark`. `mobsf` and `flowdroid` are opt-in. **CodeQL stays removed** (don't reintroduce). Navigation handles only call/type relations; dataflow/taint is covered by semgrep taint + the AI hunting line (`rules/ai/hunting.md`). Choose nav backends by benchmark (`nav_benchmark.py` + `benchmarks/*.json`), not by reputation.

## Adding/tuning rules

- Breadth rules: prefer engine packs — add a Semgrep registry pack or a small local rule under `queries/semgrep/`. Detekt/PMD/Lint rules ship with the engines. This skill does **not** maintain single-line detection rules.
- Deep/logic hunches: append a natural-language entry (`R-AI-*` id) to `rules/ai/hunting.md`.
- Persistent false positives: update the relevant source (`queries/` or `rules/ai/`) — never silently disable a rule.

## Verifying changes

There is no test suite. After editing scripts, run `/smoke-scan` (py_compile all scripts + each touched script's `--help` + `detect_project.py` against the sample repo). The sample Android repo is `/path/to/sample/android-project`.

## Doc sync

Behavior is documented in three places that must agree: `SKILL.md` (workflow), `CONVENTIONS.md` (schema/dedup/report), `README.md` (usage). When you change a script's flags or the workflow, update all three and keep each script's `--help` in sync.
