package com.plexicus.android

import android.app.Activity
import android.content.Context
import android.os.Bundle
import android.util.Log
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

class LoginActivity : Activity() {

    companion object {
        // VULNERABILITY: Hardcoded API key in source. PLEXICUS-RULE: ANDROID-HARDCODED-API-KEY
        const val API_KEY: String = "DEMO_VULN_ANDROID_API_KEY_NOT_REAL"

        // VULNERABILITY: HTTP endpoint (not HTTPS) for credential submission.
        // PLEXICUS-RULE: ANDROID-NETWORK-CLEARTEXT-LOGIN
        const val LOGIN_URL: String = "http://api.plexicus-demo.invalid/v1/login"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
    }

    private fun persistCredentials(username: String, password: String) {
        val prefs = getSharedPreferences("auth_prefs", Context.MODE_PRIVATE)
        // VULNERABILITY: Credentials stored as plaintext in SharedPreferences.
        // PLEXICUS-RULE: ANDROID-STORAGE-SHAREDPREFS-PLAINTEXT
        prefs.edit()
            .putString("username", username)
            .putString("password", password)
            .putString("api_key", API_KEY)
            .apply()
    }

    private fun login(username: String, password: String) {
        val url = URL(LOGIN_URL)
        val conn = url.openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.doOutput = true

            // VULNERABILITY: No certificate pinning — relies on the system trust
            // store, which is trivially MITM'd on rooted/managed devices.
            // PLEXICUS-RULE: ANDROID-NETWORK-NO-CERT-PINNING
            conn.setRequestProperty("X-API-Key", API_KEY)
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")

            OutputStreamWriter(conn.outputStream).use { w ->
                w.write("username=$username&password=$password")
            }
            val code = conn.responseCode
            // VULNERABILITY: Logging password in cleartext.
            // PLEXICUS-RULE: ANDROID-LOG-SENSITIVE-DATA
            Log.d("PlexicusLogin", "login user=$username password=$password http=$code")

            persistCredentials(username, password)
        } finally {
            conn.disconnect()
        }
    }
}
