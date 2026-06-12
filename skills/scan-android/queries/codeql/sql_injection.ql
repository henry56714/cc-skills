/**
 * @name Android SQL 注入
 * @description 用户控制的数据（Intent extras / SharedPreferences）未经过滤流入 SQLiteDatabase.rawQuery/execSQL
 * @kind path-problem
 * @id scan-android/sql-injection
 * @severity error
 * @tags security android
 */

import java
import semmle.code.java.dataflow.TaintTracking

private module SqlCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    exists(MethodCall ma |
      ma.getMethod().getName() in [
        "getStringExtra", "getIntExtra", "getLongExtra",
        "getParcelableExtra", "getSerializableExtra",
        "getStringArrayListExtra", "getExtra"
      ] and
      src.asExpr() = ma
    )
    or
    exists(MethodCall ma |
      ma.getMethod().getName() in ["getString", "getInt"] and
      ma.getMethod().getDeclaringType().hasName("SharedPreferences") and
      src.asExpr() = ma
    )
    or
    exists(MethodCall ma |
      ma.getMethod().getName() = "query" and
      ma.getMethod().getDeclaringType().hasQualifiedName("android.content", "ContentResolver") and
      src.asExpr() = ma
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall ma |
      ma.getMethod().getName() in ["rawQuery", "execSQL"] and
      ma.getMethod().getDeclaringType().hasQualifiedName("android.database.sqlite", "SQLiteDatabase") and
      sink.asExpr() = ma.getArgument(0)
    )
  }
}

module SqlFlow = TaintTracking::Global<SqlCfg>;
import SqlFlow::PathGraph

from SqlFlow::PathNode source, SqlFlow::PathNode sink
where SqlFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "R-SEC-011: SQL 注入 —— 用户控制的数据从 $@ 流向 SQL sink",
  source.getNode(), "用户输入来源"
