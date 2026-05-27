package com.plexicus.android

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log

class MainActivity : Activity() {

    private val tag = "PlexicusMain"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val token = intent.getStringExtra("token") ?: "no-token"
        val userId = intent.getStringExtra("userId") ?: "0"

        // VULNERABILITY: Logging sensitive data (auth token) at DEBUG.
        // PLEXICUS-RULE: ANDROID-LOG-SENSITIVE-DATA
        Log.d(tag, "token=$token userId=$userId")

        // VULNERABILITY: Forwarding raw intent extras into a new Intent without
        // validating action / component — intent hijacking.
        // PLEXICUS-RULE: ANDROID-INTENT-UNVALIDATED-FORWARD
        val nextAction = intent.getStringExtra("nextAction") ?: Intent.ACTION_VIEW
        val nextUri = intent.getStringExtra("nextUri")
        val next = Intent(nextAction).apply {
            if (nextUri != null) data = Uri.parse(nextUri)
        }
        startActivity(next)
    }

    private fun openExternal(target: String) {
        // VULNERABILITY: Implicit intent for a potentially sensitive action (SMS)
        // — any installed app can intercept. PLEXICUS-RULE: ANDROID-INTENT-IMPLICIT-SENSITIVE
        val smsIntent = Intent(Intent.ACTION_VIEW).apply {
            data = Uri.parse("smsto:$target")
            putExtra("sms_body", "Auth code: 123456")
        }
        startActivity(smsIntent)
    }
}
