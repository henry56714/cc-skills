"""scan-android 引擎 adapter 包。

每个引擎（regex / semgrep / joern / codeql / lint / detekt）实现 EngineAdapter
接口，把自己的输出归一化为 lib_scan.Candidate。详见 docs/architecture-v2.md。
"""
