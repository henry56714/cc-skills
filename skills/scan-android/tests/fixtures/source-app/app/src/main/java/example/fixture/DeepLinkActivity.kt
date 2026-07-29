package example.fixture

import android.app.Activity
import android.os.Bundle
import android.webkit.WebView
import java.io.File
import java.io.FileOutputStream

class DeepLinkActivity : Activity() {
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        val web = WebView(this)
        web.settings.javaScriptEnabled = true
        val url = intent.getStringExtra("url")
        web.loadUrl(url)

        val name = intent.getStringExtra("name")
        FileOutputStream(File(cacheDir, name)).use { it.write(byteArrayOf(1)) }
    }
}
