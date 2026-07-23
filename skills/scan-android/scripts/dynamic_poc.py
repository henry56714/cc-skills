#!/usr/bin/env python3
"""
P5 动态 PoC 验证 —— 通过 ADB 在真机/模拟器上验证安全发现。

对 confirmed 的安全类 finding（R-SEC-*），尝试构造最小 PoC 并在设备上执行，
把"静态确认"升级到"动态可证"，提供 exploit_output 字段。

前置条件:
  - ADB 可用且有设备/模拟器连接
  - debug APK 已安装（或可安装）
  - 目标 APK 的包名通过 --package 传入

用法:
  dynamic_poc.py --repo /path/to/project \\
                 --findings .scan/findings.json \\
                 --package com.example.app \\
                 [--apk app/build/outputs/apk/debug/app-debug.apk]

输出: 更新 findings.json 中安全类 finding 的 poc_result 字段
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib_scan import atomic_write_json, load_json


ADB_TIMEOUT = 30  # 秒


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--findings", default=".scan/findings.json")
    ap.add_argument("--package", required=True, help="目标 app 的包名")
    ap.add_argument("--apk", default=None, help="debug APK 路径（可选）")
    ap.add_argument("--device", default=None, help="ADB 设备 serial（默认第一个）")
    ap.add_argument("--dry-run", action="store_true", help="只打印 PoC 命令，不执行")
    args = ap.parse_args()

    repo = Path(args.repo).resolve()
    findings_path = repo / args.findings if not Path(args.findings).is_absolute() else Path(args.findings)

    # 检查 ADB
    adb = _find_adb()
    if not adb:
        _log("ADB 未找到，动态 PoC 不可用")
        return 1

    # 检查设备
    device = args.device or _get_first_device(adb)
    if not device:
        _log("没有已连接的 ADB 设备/模拟器，动态 PoC 跳过")
        return 1
    _log(f"使用设备: {device}")

    # 安装 APK（如果指定）
    if args.apk:
        apk_path = Path(args.apk)
        if apk_path.exists():
            _log(f"安装 APK: {apk_path.name}")
            if not args.dry_run:
                _adb(adb, device, ["install", "-r", str(apk_path)])

    # 读取 findings
    data = load_json(findings_path, default={"findings": []})
    findings = data.get("findings", [])

    # 仅处理 confirmed 的安全类 finding
    security_findings = [
        f for f in findings
        if f.get("status") == "open"
        and f.get("rule_id", "").startswith("R-SEC-")
        and not f.get("poc_result")  # 跳过已有 PoC 结果的
    ]

    _log(f"待验证的安全 finding: {len(security_findings)} 条")
    updated = 0

    for finding in security_findings:
        rule_id = finding.get("rule_id", "")
        poc_fn = _POC_REGISTRY.get(rule_id)
        if poc_fn is None:
            continue

        _log(f"验证 {rule_id} [{finding.get('id', '')}]...")
        try:
            poc_result = poc_fn(
                adb=adb,
                device=device,
                package=args.package,
                finding=finding,
                repo=repo,
                dry_run=args.dry_run,
            )
            finding["poc_result"] = poc_result
            updated += 1
            _log(f"  → {poc_result.get('status', 'unknown')}: {poc_result.get('summary', '')[:80]}")
        except Exception as e:
            _log(f"  → PoC 异常: {e}")
            finding["poc_result"] = {"status": "error", "summary": str(e)}

    if updated > 0 and not args.dry_run:
        atomic_write_json(findings_path, data)
        _log(f"已更新 {updated} 条 finding 的 poc_result")

    return 0


# ------------------------------------------------------------------
# PoC 函数注册表
# ------------------------------------------------------------------

_POC_REGISTRY: dict[str, callable] = {}


def _register_poc(rule_id: str):
    def decorator(fn):
        _POC_REGISTRY[rule_id] = fn
        return fn
    return decorator


@_register_poc("R-SEC-014")
def poc_debuggable(adb, device, package, finding, repo, dry_run, **kw) -> dict:
    """验证 android:debuggable=true：尝试 attach JDWP debugger。"""
    cmd_jdwp = ["jdwp"]
    output = _adb_shell(adb, device, cmd_jdwp, timeout=5) if not dry_run else "[dry-run]"
    # 检查包的 pid 是否出现在 JDWP 列表
    pid = _get_pid(adb, device, package) if not dry_run else "DRY"
    if pid and pid in (output or ""):
        return {
            "status": "confirmed",
            "summary": f"包 {package} (pid={pid}) 出现在 JDWP 可调试进程列表，可 attach 调试器",
            "evidence": output[:500],
            "command": f"adb -s {device} jdwp",
        }
    return {
        "status": "unconfirmed",
        "summary": "JDWP 检查未确认（进程可能未运行，或 debuggable 已在 release 构建中被覆写）",
        "command": f"adb -s {device} jdwp",
    }


@_register_poc("R-SEC-015")
def poc_allow_backup(adb, device, package, finding, repo, dry_run, **kw) -> dict:
    """验证 allowBackup=true：执行 adb backup 并检查输出大小。"""
    with tempfile.NamedTemporaryFile(suffix=".ab", delete=False) as tf:
        backup_file = tf.name
    cmd = [adb, "-s", device, "backup", "-noapk", "-noshared", package, "-f", backup_file]
    summary_str = f"adb backup -noapk {package}"
    if dry_run:
        Path(backup_file).unlink(missing_ok=True)
        return {"status": "dry-run", "summary": f"[dry-run] 会执行: {summary_str}", "command": summary_str}
    try:
        subprocess.run(cmd, capture_output=True, timeout=30)
        size = Path(backup_file).stat().st_size if Path(backup_file).exists() else 0
        Path(backup_file).unlink(missing_ok=True)
        if size > 100:
            return {
                "status": "confirmed",
                "summary": f"adb backup 成功导出 {size} 字节数据（allowBackup=true 已确认）",
                "command": summary_str,
            }
        return {
            "status": "unconfirmed",
            "summary": f"adb backup 输出 {size} 字节，可能为空（用户拒绝授权或 app 未运行）",
            "command": summary_str,
        }
    except Exception as e:
        Path(backup_file).unlink(missing_ok=True)
        return {"status": "error", "summary": str(e), "command": summary_str}


@_register_poc("R-SEC-007")
def poc_exported_component(adb, device, package, finding, repo, dry_run, **kw) -> dict:
    """验证导出组件可被任意 app 调用。"""
    # 从 finding 的 why/evidence 中提取组件名
    evidence = finding.get("evidence", "")
    import re
    m = re.search(r'android:name\s*=\s*"([^"]+)"', evidence)
    if m:
        comp_name = m.group(1)
        if not comp_name.startswith(package):
            comp_name = package + comp_name
        cmd_str = f"am start -n {comp_name}"
        if dry_run:
            return {"status": "dry-run", "summary": f"[dry-run] 会执行: adb shell {cmd_str}", "command": cmd_str}
        output = _adb_shell(adb, device, ["am", "start", "-n", comp_name])
        if output and "Error" not in output and "Exception" not in output:
            return {
                "status": "confirmed",
                "summary": f"成功通过 adb 启动导出组件 {comp_name}（无权限拒绝）",
                "evidence": output[:300],
                "command": f"adb shell {cmd_str}",
            }
        return {
            "status": "unconfirmed",
            "summary": f"启动组件 {comp_name} 时收到: {(output or '')[:100]}",
            "command": f"adb shell {cmd_str}",
        }
    return {
        "status": "skip",
        "summary": "未能从 finding 中提取组件名",
    }


@_register_poc("R-SEC-005")
def poc_cleartext_traffic(adb, device, package, finding, repo, dry_run, **kw) -> dict:
    """验证明文 HTTP：通过 adb 捕获网络流量（需要 root 或 tcpdump）。"""
    cmd_str = f"dumpsys connectivity | grep -i {package}"
    if dry_run:
        return {"status": "dry-run", "summary": f"[dry-run] 会执行: {cmd_str}", "command": cmd_str}
    output = _adb_shell(adb, device, ["dumpsys", "connectivity"])
    if output and package in output:
        return {
            "status": "partial",
            "summary": f"包 {package} 有网络连接记录，需结合 HTTP 抓包工具（mitmproxy/tcpdump）确认明文流量",
            "command": cmd_str,
        }
    return {"status": "skip", "summary": "需要抓包工具进一步确认", "command": cmd_str}


# ------------------------------------------------------------------
# 工具函数
# ------------------------------------------------------------------

def _find_adb() -> str | None:
    existing = shutil.which("adb")
    if existing:
        return existing
    candidates = [
        Path.home() / "Library" / "Android" / "sdk" / "platform-tools" / "adb",
        Path(os.environ.get("ANDROID_HOME", "")) / "platform-tools" / "adb",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return None


def _get_first_device(adb: str) -> str | None:
    try:
        out = subprocess.check_output([adb, "devices"], text=True, timeout=5)
        for line in out.splitlines():
            if "\tdevice" in line:
                return line.split("\t")[0]
    except Exception:
        pass
    return None


def _adb(adb: str, device: str, args: list[str], timeout: int = ADB_TIMEOUT) -> str:
    try:
        return subprocess.check_output(
            [adb, "-s", device] + args,
            text=True, timeout=timeout, stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        return str(e)


def _adb_shell(adb: str, device: str, cmd: list[str], timeout: int = ADB_TIMEOUT) -> str:
    return _adb(adb, device, ["shell"] + cmd, timeout=timeout)


def _get_pid(adb: str, device: str, package: str) -> str | None:
    out = _adb_shell(adb, device, ["pidof", package])
    pid = out.strip()
    return pid if pid.isdigit() else None


def _log(msg: str) -> None:
    print(f"[dynamic_poc] {msg}", flush=True)


if __name__ == "__main__":
    sys.exit(main())
