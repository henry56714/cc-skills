# AI Skills Collection

**[中文](README.zh.md)** | **English**

A collection of ready-to-use AI Skills, each targeting a specific task type. Trigger with a single natural-language phrase and the AI handles the full workflow automatically.

Skills follow a common format (SKILL.md + scripts + rules) and are compatible with [Claude Code](https://claude.ai/code) and other AI coding tools that support custom skills or plugins.

| Skill | Trigger | What it does |
|---|---|---|
| **[scan-android](#scan-android)** | `/scan-android` · "scan code" | Source/APK scanner for any Android project (security, stability & performance defects) — outputs structured findings and a Markdown report |

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

---

## License

MIT
