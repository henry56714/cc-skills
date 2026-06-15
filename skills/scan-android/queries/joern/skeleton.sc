/**
 * 代码骨架提取脚本 —— 供 AI 狩猎支线（step 5.5.2）使用。
 *
 * 用法（由 orchestrator 调用）:
 *   joern --script skeleton.sc --param srcDir=/abs/path --param outFile=/abs/path/skeleton.json
 *
 * 输出: JSON 数组，每个元素对应一个非外部类型，含字段列表和方法列表（不含方法体）。
 */

import io.shiftleft.semanticcpg.language._
import scala.collection.mutable.ArrayBuffer
import ujson._

@main def exec(srcDir: String, outFile: String): Unit = {
  importCode(srcDir, "android-project")

  val skeleton = ArrayBuffer[ujson.Obj]()

  cpg.typeDecl
    .filter(_.isExternal == false)
    .filter { t =>
      val f = t.file.name.headOption.getOrElse("")
      // 只保留项目源码，排除编译临时目录、系统临时目录和 build 产物
      f.nonEmpty && !f.startsWith("/var/folders/") && !f.startsWith("/tmp/") &&
      !f.contains("/build/") && !f.contains("/jimple2cpg") && !f.contains("/.gradle/")
    }
    .foreach { t =>
      val fields = t.member.map { m =>
        m.typeFullName.split("\\.").last + " " + m.name
      }.toSeq

      val methods = t.method
        .filterNot(_.name.startsWith("<"))
        .map { m =>
          ujson.Obj(
            "name"    -> m.name,
            "line"    -> m.lineNumber.getOrElse(0),
            "callers" -> m.caller.size
          )
        }.toSeq

      skeleton += ujson.Obj(
        "name"    -> t.name,
        "file"    -> t.file.name.headOption.getOrElse(""),
        "fields"  -> ujson.Arr(fields.map(ujson.Str(_)): _*),
        "methods" -> ujson.Arr(methods: _*)
      )
    }

  os.write.over(os.Path(outFile), ujson.write(skeleton.toSeq, indent = 2))
  println(s"[skeleton] ${skeleton.size} 个类型写入 $outFile")
}
