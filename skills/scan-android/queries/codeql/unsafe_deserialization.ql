/**
 * @name Android 不安全反序列化
 * @description 不可信输入（网络流 / Intent extras）流向 ObjectInputStream，可能触发 gadget 链 RCE
 * @kind path-problem
 * @id scan-android/unsafe-deserialization
 * @severity error
 * @tags security android
 */

import java
import semmle.code.java.dataflow.TaintTracking

private module DeserCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    exists(MethodCall ma |
      ma.getMethod().getName() in ["getInputStream", "openStream"] and
      src.asExpr() = ma
    )
    or
    exists(MethodCall ma |
      ma.getMethod().getName() in ["getSerializableExtra", "getByteArrayExtra"] and
      src.asExpr() = ma
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(ClassInstanceExpr no |
      no.getConstructedType().hasQualifiedName("java.io", "ObjectInputStream") and
      sink.asExpr() = no.getArgument(0)
    )
  }
}

module DeserFlow = TaintTracking::Global<DeserCfg>;
import DeserFlow::PathGraph

from DeserFlow::PathNode source, DeserFlow::PathNode sink
where DeserFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "R-SEC-019: 不安全反序列化 —— 不可信输入 $@ 流向 ObjectInputStream",
  source.getNode(), "不可信输入来源"
