/**
 * @name Android Intent 重定向
 * @description 从 Intent extras 取出的对象被直接转发给组件启动方法，可能导致越权访问
 * @kind path-problem
 * @id scan-android/intent-redirection
 * @severity error
 * @tags security android
 */

import java
import semmle.code.java.dataflow.TaintTracking

private module IntentCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    exists(MethodCall ma |
      ma.getMethod().getName() in ["getParcelableExtra", "getSerializableExtra"] and
      src.asExpr() = ma
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall ma |
      ma.getMethod().getName() in [
        "startActivity", "startActivityForResult", "startService",
        "sendBroadcast", "bindService"
      ] and
      sink.asExpr() = ma.getArgument(0)
    )
  }
}

module IntentFlow = TaintTracking::Global<IntentCfg>;
import IntentFlow::PathGraph

from IntentFlow::PathNode source, IntentFlow::PathNode sink
where IntentFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "R-SEC-016: Intent 重定向 —— 从 extra 取出的 $@ 被直接转发给 Android 组件启动方法",
  source.getNode(), "Intent extra 来源"
