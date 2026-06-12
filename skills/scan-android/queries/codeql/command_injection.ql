/**
 * @name Android 命令注入
 * @description 用户控制的 Intent extras 流入 Runtime.exec() 或 ProcessBuilder
 * @kind path-problem
 * @id scan-android/command-injection
 * @severity error
 * @tags security android
 */

import java
import semmle.code.java.dataflow.TaintTracking

private module CmdCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    exists(MethodCall ma |
      ma.getMethod().getName() in [
        "getStringExtra", "getIntExtra", "getParcelableExtra"
      ] and
      src.asExpr() = ma
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall ma |
      ma.getMethod().getName() = "exec" and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
      sink.asExpr() = ma.getArgument(0)
    )
    or
    exists(ClassInstanceExpr no |
      no.getConstructedType().hasQualifiedName("java.lang", "ProcessBuilder") and
      sink.asExpr() = no.getArgument(0)
    )
  }
}

module CmdFlow = TaintTracking::Global<CmdCfg>;
import CmdFlow::PathGraph

from CmdFlow::PathNode source, CmdFlow::PathNode sink
where CmdFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "R-SEC-012: 命令注入 —— 用户输入 $@ 流向 Runtime.exec() 或 ProcessBuilder",
  source.getNode(), "用户输入来源"
