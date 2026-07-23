"""引擎 adapter 接口（v2 架构 §2 决策1：引擎可插拔）。

每个引擎写一个 adapter，把自身输出翻译成归一化的 Candidate。run_engines.py
编排器只依赖本接口，不关心具体引擎，从而实现"加引擎不动管线"。
"""

from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib_scan import Candidate


class InstallationError(Exception):
    """引擎已被配置为必需，但安装（下载）失败。

    由 adapter 的 is_available() 抛出，区别于"未启用"（返回 False）：
    - 未启用   → 返回 (False, reason)，run_engines 静默跳过
    - 安装失败 → 抛出 InstallationError，run_engines 中止整次扫描并报错
    """


@dataclass
class ScanContext:
    """传给每个 adapter 的统一输入。"""

    repo: Path
    scope_files: list[str]
    rules_dir: Path
    max_per_rule: int = 100
    detect_info: dict = field(default_factory=dict)
    opt_in_engines: list[str] = field(default_factory=list)
    excluded_engines: list[str] = field(default_factory=list)


@dataclass
class AdapterResult:
    """每个 adapter 的统一输出。"""

    engine: str
    candidates: list[Candidate] = field(default_factory=list)
    notes: list[dict] = field(default_factory=list)
    rules_run: int = 0
    rules_total: int = 0
    available: bool = True
    unavailable_reason: str = ""


class EngineAdapter(ABC):
    """所有引擎 adapter 的基类。"""

    #: 引擎名，进入 Candidate.engine 与 run_engines 输出的 engines_used
    name: str = "base"

    @abstractmethod
    def is_available(self, ctx: ScanContext) -> tuple[bool, str]:
        """返回 (是否可用, 不可用原因)。原因用于降级提示。"""
        raise NotImplementedError

    @abstractmethod
    def run(self, ctx: ScanContext) -> AdapterResult:
        """执行扫描，返回归一化候选。仅在 is_available 为真时调用。"""
        raise NotImplementedError
