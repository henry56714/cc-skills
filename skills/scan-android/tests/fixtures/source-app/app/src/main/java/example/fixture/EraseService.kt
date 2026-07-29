package example.fixture

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import java.io.File

class EraseService : Service() {
    private val binder = object : Binder() {
        fun erase(relativePath: String): Boolean {
            return File(filesDir, relativePath).delete()
        }
    }

    override fun onBind(intent: Intent?): IBinder = binder
}
