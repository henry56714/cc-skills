"""scan-android 脚本共享库：JSON I/O、id 计算、时间戳、规则解析。"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Iterable


CST = timezone(timedelta(hours=8))


def now_iso() -> str:
    """返回本地 CST 时间的 ISO8601 字符串（秒精度，带时区）。"""
    return datetime.now(CST).replace(microsecond=0).isoformat()


def iso_to_date(iso: str) -> str:
    """YYYY-MM-DD（用于报告渲染）。"""
    return iso.split("T", 1)[0]


def short_commit(commit: str, length: int = 8) -> str:
    return commit[:length] if commit else ""


def finding_id(file_: str, line: int, category: str) -> str:
    raw = f"{file_}:{line}:{category}".encode("utf-8")
    return hashlib.sha1(raw).hexdigest()


def load_json(path: str | Path, default: Any = None) -> Any:
    p = Path(path)
    if not p.exists():
        return default
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


def atomic_write_json(path: str | Path, data: Any, *, indent: int = 2) -> None:
    """写入到 path.tmp 后原子 rename，避免半写状态。"""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=p.name + ".", suffix=".tmp", dir=str(p.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=indent)
            f.write("\n")
        os.replace(tmp_name, p)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# 规则解析
# ---------------------------------------------------------------------------


@dataclass
class Rule:
    """从 rules/<check>.md 解析出的单条规则。"""

    rule_id: str  # 例 R-STB-007
    title: str
    category: str
    severity: str
    pattern: str
    multiline: bool = False
    includes: list[str] = field(default_factory=list)
    excludes: list[str] = field(default_factory=list)
    raw: str = ""  # 原始段落文本，便于调试

    @property
    def check(self) -> str:
        """从 rule_id 推导检查类别：R-SEC-* → security, R-STB-* → stability, etc."""
        prefix = self.rule_id.split("-")[1]
        return _CHECK_PREFIX_MAP[prefix]


_CHECK_PREFIX_MAP = {
    "SEC": "security",
    "STB": "stability",
    "PRF": "perf",
}


_HEADER_RE = re.compile(r"^##\s+(R-[A-Z]+-\d+)\s+[—–-]+\s+(.+?)\s*$", re.MULTILINE)
_BACKTICK_RE = re.compile(r"`([^`]+)`")


def parse_rules_file(path: str | Path) -> list[Rule]:
    text = Path(path).read_text(encoding="utf-8")
    rules: list[Rule] = []

    matches = list(_HEADER_RE.finditer(text))
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[start:end]
        rule = _parse_rule_body(m.group(1), m.group(2).strip(), body)
        if rule is not None:
            rules.append(rule)
    return rules


def _parse_rule_body(rule_id: str, title: str, body: str) -> Rule | None:
    category = _field(body, "Category")
    severity = _field(body, "Severity")
    pattern_line = _field_line(body, "Pattern")
    multiline = False
    if pattern_line is None:
        pattern_line = _field_line(body, r"Pattern\s*\(multiline\)")
        multiline = pattern_line is not None
    if pattern_line is None or category is None or severity is None:
        return None
    pattern = _first_backtick(pattern_line)
    if not pattern:
        return None

    include_line = _field_line(body, "Include") or ""
    exclude_line = _field_line(body, "Exclude") or ""
    includes = _all_backticks(include_line)
    excludes = _all_backticks(exclude_line)

    return Rule(
        rule_id=rule_id,
        title=title,
        category=category.strip(),
        severity=severity.strip(),
        pattern=pattern,
        multiline=multiline,
        includes=includes,
        excludes=excludes,
        raw=body,
    )


def _field(body: str, field_name: str) -> str | None:
    line = _field_line(body, field_name)
    if line is None:
        return None
    bt = _first_backtick(line)
    if bt is not None:
        return bt
    # 无反引号时取冒号后文本
    m = re.search(
        rf"-\s*\*\*{field_name}\s*:\*\*\s*(.+?)\s*$", body, re.MULTILINE
    )
    return m.group(1) if m else None


def _field_line(body: str, field_name: str) -> str | None:
    """抓取 `- **Field:** ...` 整行（含冒号后内容）。"""
    m = re.search(
        rf"^-\s*\*\*{field_name}\s*:\*\*\s*(.*)$", body, re.MULTILINE
    )
    return m.group(1) if m else None


def _first_backtick(s: str) -> str | None:
    m = _BACKTICK_RE.search(s)
    return m.group(1) if m else None


def _all_backticks(s: str) -> list[str]:
    return _BACKTICK_RE.findall(s)


# ---------------------------------------------------------------------------
# glob 展开（用于 Include/Exclude）
# ---------------------------------------------------------------------------


def expand_brace_globs(patterns: Iterable[str]) -> list[str]:
    """展开 **/*.{java,kt} → [**/*.java, **/*.kt]。仅处理单层 {}。"""
    out: list[str] = []
    for p in patterns:
        out.extend(_expand_one(p))
    return out


def _expand_one(p: str) -> list[str]:
    m = re.search(r"\{([^{}]+)\}", p)
    if not m:
        return [p]
    parts = [x.strip() for x in m.group(1).split(",")]
    pre, post = p[: m.start()], p[m.end() :]
    return [pre + part + post for part in parts]


# ---------------------------------------------------------------------------
# severity 排序键
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "major": 1, "minor": 2, "info": 3}


def severity_rank(sev: str) -> int:
    return SEVERITY_ORDER.get(sev, 99)


# ---------------------------------------------------------------------------
# 归一化候选契约（v2 架构 §4）
# ---------------------------------------------------------------------------


@dataclass
class Candidate:
    """所有引擎 adapter 的统一输出格式。

    无论候选来自正则 / Semgrep / Joern / CodeQL / Lint，后续的 LLM 验证、去重、
    报告都只消费本契约，不关心来源引擎。详见 docs/architecture-v2.md §4。
    """

    engine: str            # 产出引擎: regex|semgrep|joern|codeql|lint|detekt
    rule_id: str           # 我们的统一 id（经 taxonomy 映射），如 R-SEC-001
    file: str              # 相对仓库根，正斜杠
    line: int              # 1-based 主要违规行
    category: str = ""     # 如 security/hardcoded-secret
    severity: str = ""     # critical|major|minor|info
    native_rule_id: str = ""   # 引擎自己的 id，可追溯
    end_line: int | None = None
    snippet: str = ""
    # 跨文件 source→sink 路径（污点引擎产出），元素含 {file,line,message}
    dataflow_path: list[dict] = field(default_factory=list)
    message: str = ""      # 引擎原始描述

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "engine": self.engine,
            "rule_id": self.rule_id,
            "file": self.file,
            "line": self.line,
            "category": self.category,
            "severity": self.severity,
            "native_rule_id": self.native_rule_id,
            "snippet": self.snippet,
            "message": self.message,
        }
        if self.end_line is not None:
            d["end_line"] = self.end_line
        if self.dataflow_path:
            d["dataflow_path"] = self.dataflow_path
        return d
