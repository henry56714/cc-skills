"""scan-android 引擎 adapter 包。

每个引擎（semgrep / detekt / pmd / lint / mobsf / flowdroid）实现 EngineAdapter
接口，把自己的输出归一化为 lib_scan.Candidate。详见 docs/architecture-v2.md。
（跨文件调用/类型导航由 tree-sitter 提供，见 scripts/nav_tools.py，非候选生成引擎。）
"""
