package example.fixture

import java.io.File

class SafeFileStore(private val root: File) {
    fun child(name: String): File {
        require('/' !in name && '\\' !in name && name != "..")
        val file = File(root, name).canonicalFile
        require(file.parentFile == root.canonicalFile)
        return file
    }
}
