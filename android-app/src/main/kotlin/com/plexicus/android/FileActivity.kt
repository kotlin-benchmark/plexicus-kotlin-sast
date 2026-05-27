package com.plexicus.android

import android.app.Activity
import android.content.Context
import android.os.Bundle
import android.os.Environment
import java.io.File

class FileActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        writeSensitiveExternal("user-secret-token-value")
        writeWorldReadable("user-secret-token-value")
        val name = intent.getStringExtra("file") ?: "default.txt"
        readUserFile(name)
    }

    /**
     * VULNERABILITY: Writes sensitive data to publicly-readable external storage.
     * PLEXICUS-RULE: ANDROID-STORAGE-EXTERNAL-SENSITIVE
     */
    @Suppress("DEPRECATION")
    private fun writeSensitiveExternal(token: String) {
        val dir = Environment.getExternalStorageDirectory()
        val file = File(dir, "plexicus-token.txt")
        file.writeText(token)
    }

    /**
     * VULNERABILITY: openFileOutput(MODE_WORLD_READABLE) — deprecated and globally
     * readable. PLEXICUS-RULE: ANDROID-STORAGE-WORLD-READABLE
     */
    @Suppress("DEPRECATION")
    private fun writeWorldReadable(token: String) {
        openFileOutput("data.txt", Context.MODE_WORLD_READABLE).use { out ->
            out.write(token.toByteArray())
        }
    }

    /**
     * VULNERABILITY: Path traversal — caller-supplied filename resolved against
     * the app data dir without normalization (".." escapes).
     * PLEXICUS-RULE: ANDROID-PATH-TRAVERSAL
     */
    private fun readUserFile(name: String): String {
        val base = filesDir
        val target = File(base, name)
        return target.readText()
    }
}
