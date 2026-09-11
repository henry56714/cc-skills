# AI Skills Collection

**[中文](README.zh.md)** | **English**

A collection of ready-to-use AI Skills, each targeting a specific task type. Trigger with a single natural-language phrase and the AI handles the full workflow automatically.

Each skill is a self-contained directory driven by a `SKILL.md` (some also bundle scripts and rules), compatible with [Claude Code](https://claude.ai/code) and other AI coding tools that support custom skills or plugins.

| Skill | Trigger | What it does |
|---|---|---|
| **[scan-android](#scan-android)** | `/scan-android` · "scan code" | Source/APK scanner for any Android project (security, stability & performance defects) — outputs structured findings and a Markdown report |
| **[teach](#teach)** | "explain this chapter" · "why does X work?" | Turns a chapter or a single question into a beginner-friendly deep-learning lecture, optionally written to a Markdown file (Chinese output) |
| **[improve-notes](#improve-notes)** | "improve my notes" · "polish this chapter's notes" | Upgrades rough study notes into self-contained professional review material, grounded in full reference sources (Chinese output) |

---

## Installation

Using Claude Code as an example, copy (or symlink) the skill directory into your skills path:

```bash
cp -r skills/scan-android ~/.claude/skills/scan-android
# or use a symlink
ln -s /path/to/cc-skills/skills/scan-android ~/.claude/skills/scan-android
```

For other AI tools, refer to their documentation on installing custom skills or plugins, and point the skill directory to the tool's load path.

Each skill directory works at any location — no hardcoded paths inside, ready to use after download.

---

## Skills

### scan-android

An incremental code scanner for **any Android repository**, covering three universal dimensions:

| Dimension | Focus |
|---|---|
| **security** | Hardcoded secrets, weak crypto, any-cert TLS trust, WebView config, exported components, plaintext traffic, SQL injection, etc. |
| **stability** | Resource leaks, lifecycle leaks, NPE paths, concurrency bugs, WakeLock, foreground service timing, ConcurrentModification, etc. |
| **perf** | Main-thread I/O, onDraw allocations, hot-path reflection, Bitmap OOM, unbounded caches, batch DB writes without transactions, etc. |

Rules are self-gating by technology — only patterns relevant to the tech stack in use will fire. Zero configuration required for any Android project. Multiple runs accumulate coverage via dedup + ledger.

**Trigger**

```
/scan-android
/scan-android --module=app
/scan-android --full
```

Or in natural language: "scan the code", "find bugs in the codebase", "run a stability scan on the app module"

**Output**

```
.scan/
  findings.json        ← structured findings (open / fixed / wontfix)
  ledger.json          ← run history + coverage map
  reports/
    findings.md        ← human-readable report (critical → major → minor → info)
```

**Requirements:** Python 3.8+, no third-party packages — standard library only.

See [`skills/scan-android/README.md`](skills/scan-android/README.md) for full documentation.

### teach

A teaching skill that explains a **technical chapter or a single question** the way a good lecturer would — so a complete beginner can follow. Originally written for 《动手学深度学习》 (Dive into Deep Learning, PyTorch edition) but works on any technical material: IPython notebooks, papers, source code.

- **Intuition first** — everyday analogies before terminology; math only after the intuition, with every symbol explained.
- **Example-driven** — concrete numbers and small tensors instead of abstract statements.
- **Code-aware** — explains what each code block does and why, mapped back to the formulas.
- **Grounded** — strictly faithful to the source material; never invents concepts, formulas, or numbers.

Optionally writes the lecture to a given Markdown file: creates it if missing, appends under a new `##` heading if it already exists — never overwrites existing content. Output in Chinese.

**Trigger** — point it at a chapter file or ask a question, in natural language:

```
explain chapter_convolutional-modern/resnet.ipynb, write to notes/resnet.md
why does BatchNorm speed up convergence?
```

Prompt-only skill: a single [`SKILL.md`](skills/teach/SKILL.md), no scripts, no dependencies.

### improve-notes

Upgrades a rough chapter note into a **self-contained professional review document**. Given a note file and reference materials (IPython notebooks, Markdown, code), it first reads every source exhaustively — every code cell, output, and exercise included — then rewrites the note section by section.

Each `##` section becomes an independent, self-contained card (Anki-friendly) covering: the problem it solves, intuition, rigorous math with symbol-by-symbol explanations, links to the reference code, hyperparameters and engineering practice, and common pitfalls. Grounded strictly in the references — nothing invented; gaps are marked explicitly rather than filled with guesses.

**Trigger** — name the note file and its reference material(s):

```
improve my notes in src/06chapter_convolutional-neural-networks/06chapter_convolutional-neural-networks_note.md,
using chapter_convolutional-neural-networks/ as reference
```

Prompt-only skill: a single [`SKILL.md`](skills/improve-notes/SKILL.md), no scripts, no dependencies.

---

## License

MIT
