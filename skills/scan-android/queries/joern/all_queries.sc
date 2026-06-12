/**
 * scan-android Joern CPGQL 查询脚本 (v2)
 *
 * 用法（由 joern_adapter.py 调用）:
 *   joern --script all_queries.sc --param srcDir=/abs/path --param outFile=/tmp/results.json
 *
 * 输出: JSON 数组写入 outFile，每个元素是一个 Candidate 结构体。
 */

import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import scala.collection.mutable.ArrayBuffer
import ujson._

@main def exec(srcDir: String, outFile: String): Unit = {
  // 导入源码构建 CPG
  importCode(srcDir, "android-project")

  val findings = ArrayBuffer[ujson.Obj]()

  def finding(
    ruleId: String,
    nativeId: String,
    category: String,
    severity: String,
    file: String,
    line: Int,
    snippet: String,
    message: String,
    dataflowPath: Seq[Map[String, Any]] = Seq.empty
  ): ujson.Obj = {
    val base = ujson.Obj(
      "rule_id"        -> ruleId,
      "native_rule_id" -> nativeId,
      "category"       -> category,
      "severity"       -> severity,
      "file"           -> file,
      "line"           -> line,
      "snippet"        -> snippet.take(300),
      "message"        -> message
    )
    if (dataflowPath.nonEmpty) {
      base("dataflow_path") = ujson.Arr(dataflowPath.map { step =>
        ujson.Obj(
          "file"    -> step.getOrElse("file", "").toString,
          "line"    -> step.getOrElse("line", 0).asInstanceOf[Any].toString.toIntOption.getOrElse(0),
          "message" -> step.getOrElse("message", "").toString
        )
      }: _*)
    }
    base
  }

  // ============================================================
  // R-SEC-011: SQL 注入 —— rawQuery/execSQL 参数含字符串拼接
  // ============================================================
  try {
    cpg.call.nameExact("rawQuery", "execSQL")
      .where(_.argument.order(1).isCall.nameExact("<operator>.addition"))
      .foreach { c =>
        val f = c.file.name.headOption.getOrElse("")
        val ln = c.lineNumber.getOrElse(-1)
        findings += finding(
          "R-SEC-011", "joern-sql-injection-concat",
          "security/sql-injection", "critical",
          f, ln, c.code,
          "SQL 注入：rawQuery/execSQL 第一个参数含字符串拼接"
        )
      }
  } catch { case e: Throwable =>
    System.err.println(s"[joern] R-SEC-011 查询失败: ${e.getMessage}")
  }

  // ============================================================
  // R-SEC-011: SQL 注入 —— 跨文件污点追踪
  // ============================================================
  try {
    implicit val engineContext: EngineContext = EngineContext()
    val sqlSources = cpg.call.nameExact(
      "getStringExtra", "getIntExtra", "getParcelableExtra", "getSerializableExtra",
      "getQuery", "getQueryParameter", "readLine"
    )
    val sqlSinks = cpg.call.nameExact("rawQuery", "execSQL")
    sqlSinks.reachableByFlows(sqlSources).foreach { flow =>
      val pathNodes = flow.elements.collect { case c: io.shiftleft.codepropertygraph.generated.nodes.Call =>
        Map[String, Any](
          "file"    -> c.file.name.headOption.getOrElse(""),
          "line"    -> c.lineNumber.getOrElse(-1),
          "message" -> c.code.take(100)
        )
      }
      val sink = flow.elements.lastOption
      sink.foreach { s =>
        val sCall = s.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Call]
        findings += finding(
          "R-SEC-011", "joern-sql-injection-taint",
          "security/sql-injection", "critical",
          sCall.file.name.headOption.getOrElse(""),
          sCall.lineNumber.getOrElse(-1),
          sCall.code,
          "SQL 注入：跨文件污点路径从用户输入到达 SQL sink",
          pathNodes
        )
      }
    }
  } catch { case e: Throwable =>
    System.err.println(s"[joern] R-SEC-011 taint 查询失败: ${e.getMessage}")
  }

  // ============================================================
  // R-SEC-012: 命令注入 —— Runtime.exec / ProcessBuilder 跨文件污点
  // ============================================================
  try {
    implicit val engineContext: EngineContext = EngineContext()
    val cmdSources = cpg.call.nameExact(
      "getStringExtra", "getIntExtra", "getParcelableExtra", "readLine",
      "getQuery", "getQueryParameter", "getRequestParameter"
    )
    val cmdSinks = cpg.call.nameExact("exec").where(
      _.receiver.isCall.nameExact("getRuntime")
    )
    cmdSinks.reachableByFlows(cmdSources).foreach { flow =>
      val pathNodes = flow.elements.collect { case c: io.shiftleft.codepropertygraph.generated.nodes.Call =>
        Map[String, Any](
          "file"    -> c.file.name.headOption.getOrElse(""),
          "line"    -> c.lineNumber.getOrElse(-1),
          "message" -> c.code.take(100)
        )
      }
      val sink = flow.elements.lastOption
      sink.foreach { s =>
        val sCall = s.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Call]
        findings += finding(
          "R-SEC-012", "joern-command-injection-taint",
          "security/command-injection", "critical",
          sCall.file.name.headOption.getOrElse(""),
          sCall.lineNumber.getOrElse(-1),
          sCall.code,
          "命令注入：跨文件污点路径从用户输入到达 Runtime.exec()",
          pathNodes
        )
      }
    }
  } catch { case e: Throwable =>
    System.err.println(s"[joern] R-SEC-012 taint 查询失败: ${e.getMessage}")
  }

  // ============================================================
  // R-SEC-016: Intent 重定向 —— getParcelableExtra 结果流向 startActivity
  // ============================================================
  try {
    implicit val engineContext: EngineContext = EngineContext()
    val intentSources = cpg.call.nameExact("getParcelableExtra", "getSerializableExtra")
    val intentSinks = cpg.call.nameExact(
      "startActivity", "startActivityForResult", "startService",
      "sendBroadcast", "bindService"
    )
    intentSinks.reachableByFlows(intentSources).foreach { flow =>
      val pathNodes = flow.elements.collect { case c: io.shiftleft.codepropertygraph.generated.nodes.Call =>
        Map[String, Any](
          "file"    -> c.file.name.headOption.getOrElse(""),
          "line"    -> c.lineNumber.getOrElse(-1),
          "message" -> c.code.take(100)
        )
      }
      flow.elements.lastOption.foreach { s =>
        val sCall = s.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Call]
        findings += finding(
          "R-SEC-016", "joern-intent-redirection",
          "security/intent-redirection", "critical",
          sCall.file.name.headOption.getOrElse(""),
          sCall.lineNumber.getOrElse(-1),
          sCall.code,
          "Intent 重定向：extra 中取出的 Intent 被直接转发，可借本 app 权限访问私有组件",
          pathNodes
        )
      }
    }
  } catch { case e: Throwable =>
    System.err.println(s"[joern] R-SEC-016 taint 查询失败: ${e.getMessage}")
  }

  // ============================================================
  // R-STB-001: Cursor 未关闭 —— rawQuery/query 返回值在当前方法无 close()
  // ============================================================
  try {
    cpg.call.nameExact("rawQuery", "query")
      .where(_.inAssignment)
      .filterNot { c =>
        // 在同一方法内找到 close() 调用
        val method = c.method
        method.call.nameExact("close").nonEmpty
      }
      .foreach { c =>
        findings += finding(
          "R-STB-001", "joern-cursor-not-closed",
          "stability/resource-leak-cursor", "major",
          c.file.name.headOption.getOrElse(""),
          c.lineNumber.getOrElse(-1),
          c.code,
          "Cursor 可能未关闭：rawQuery/query 结果在方法内未发现 close() 调用"
        )
      }
  } catch { case e: Throwable =>
    System.err.println(s"[joern] R-STB-001 查询失败: ${e.getMessage}")
  }

  // ============================================================
  // R-STB-004: 静态字段持有 Context/Activity/View
  // ============================================================
  try {
    cpg.member
      .filter(_.typeFullName.matches(".*(Activity|Context|View|Fragment|Dialog|Window).*"))
      .filter(c => c.modifier.exists(_.modifierType == "STATIC"))
      .filterNot(c => c.modifier.exists(_.modifierType == "FINAL"))  // static final 通常是 Application context
      .foreach { m =>
        val f = m.file.name.headOption.getOrElse("")
        val ln = m.lineNumber.getOrElse(-1)
        findings += finding(
          "R-STB-004", "joern-static-context-leak",
          "stability/static-context-leak", "critical",
          f, ln, m.code,
          s"静态字段 '${m.name}' 持有 ${m.typeFullName}，阻止 GC 回收"
        )
      }
  } catch { case e: Throwable =>
    System.err.println(s"[joern] R-STB-004 查询失败: ${e.getMessage}")
  }

  // ============================================================
  // R-PRF-001: 主线程 I/O —— 生命周期方法调用 File I/O（调用图可达性）
  // ============================================================
  try {
    val uiEntryPoints = cpg.method.nameExact(
      "onCreate", "onStart", "onResume", "onCreateView",
      "onClick", "onTouch", "onItemClick"
    )
    val ioSinks = cpg.call.nameExact(
      "read", "write", "openStream", "newInputStream", "newOutputStream"
    ).filter(_.methodFullName.matches(".*\\.(File|FileInputStream|FileOutputStream|RandomAccessFile|InputStream|OutputStream).*"))

    ioSinks.reachableByFlows(uiEntryPoints.methodReturn.toReturn).foreach { flow =>
      flow.elements.lastOption.foreach { s =>
        val sCall = s.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Call]
        findings += finding(
          "R-PRF-001", "joern-main-thread-io",
          "perf/main-thread-io", "major",
          sCall.file.name.headOption.getOrElse(""),
          sCall.lineNumber.getOrElse(-1),
          sCall.code,
          "主线程 I/O：从 UI 生命周期方法可达文件 I/O 操作（可能导致 ANR）"
        )
      }
    }
  } catch { case e: Throwable =>
    System.err.println(s"[joern] R-PRF-001 查询失败: ${e.getMessage}")
  }

  // ============================================================
  // R-PRF-003: 主线程网络 —— 生命周期方法调用同步 HTTP
  // ============================================================
  try {
    val uiEntries = cpg.method.nameExact(
      "onCreate", "onStart", "onResume", "onCreateView", "onClick"
    )
    val netSinks = cpg.call.nameExact("execute")
      .filter(_.methodFullName.matches(".*\\.Call.*|.*okhttp3.*|.*retrofit2.*|.*OkHttp.*|.*Retrofit.*"))

    netSinks.reachableByFlows(uiEntries.methodReturn.toReturn).foreach { flow =>
      flow.elements.lastOption.foreach { s =>
        val sCall = s.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Call]
        findings += finding(
          "R-PRF-003", "joern-main-thread-network",
          "perf/main-thread-network", "critical",
          sCall.file.name.headOption.getOrElse(""),
          sCall.lineNumber.getOrElse(-1),
          sCall.code,
          "主线程网络：从 UI 生命周期方法可达同步 HTTP 调用（ANR + NetworkOnMainThreadException）"
        )
      }
    }
  } catch { case e: Throwable =>
    System.err.println(s"[joern] R-PRF-003 查询失败: ${e.getMessage}")
  }

  // ============================================================
  // R-STB-023: 外部输入未经防御性解析
  // ============================================================
  try {
    implicit val engineContext: EngineContext = EngineContext()
    val parseSources = cpg.call.nameExact(
      "getStringExtra", "getQueryParameter", "readLine", "nextLine"
    )
    val parseSinks = cpg.call.nameExact(
      "parseInt", "parseLong", "parseFloat", "parseDouble",
      "toInt", "toLong", "toFloat", "toDouble"
    )
    parseSinks.reachableByFlows(parseSources).foreach { flow =>
      flow.elements.lastOption.foreach { s =>
        val sCall = s.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Call]
        findings += finding(
          "R-STB-023", "joern-unsafe-parse",
          "stability/unsafe-parse", "major",
          sCall.file.name.headOption.getOrElse(""),
          sCall.lineNumber.getOrElse(-1),
          sCall.code,
          "外部输入未经防御性解析：用户/外部输入直接传入 parseInt 等，无异常处理则一条畸形输入即可崩溃"
        )
      }
    }
  } catch { case e: Throwable =>
    System.err.println(s"[joern] R-STB-023 taint 查询失败: ${e.getMessage}")
  }

  // ============================================================
  // R-STB-016: WakeLock acquire 但方法内无 release
  // ============================================================
  try {
    cpg.call.nameExact("acquire")
      .filter(_.methodFullName.matches(".*WakeLock.*|.*WifiLock.*"))
      .filterNot { c =>
        c.method.call.nameExact("release").exists(
          _.methodFullName.matches(".*WakeLock.*|.*WifiLock.*")
        )
      }
      .foreach { c =>
        findings += finding(
          "R-STB-016", "joern-wakelock-no-release",
          "stability/wakelock-leak", "major",
          c.file.name.headOption.getOrElse(""),
          c.lineNumber.getOrElse(-1),
          c.code,
          "WakeLock.acquire() 在同一方法内未发现配对的 release()，可能导致设备无法入睡"
        )
      }
  } catch { case e: Throwable =>
    System.err.println(s"[joern] R-STB-016 查询失败: ${e.getMessage}")
  }

  // ============================================================
  // 写出结果
  // ============================================================
  val json = ujson.Arr(findings.toSeq: _*)
  os.write.over(os.Path(outFile), ujson.write(json, indent = 2))
  println(s"[joern] 写出 ${findings.size} 条发现到 $outFile")
}
