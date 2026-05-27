package com.plexicus.android.BroadcastReceiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Insecure broadcast receiver — paired with the exported, permission-less
 * <receiver> entry in AndroidManifest.xml.
 */
class InsecureReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        // VULNERABILITY: No permission check on the inbound broadcast — any app
        // can fire the matching action and trigger the handler.
        // PLEXICUS-RULE: ANDROID-BROADCAST-RECEIVER-NO-PERMISSION-CHECK
        val action = intent.action ?: return
        val payload = intent.getStringExtra("payload") ?: ""

        when (action) {
            "com.plexicus.android.ACTION_ADMIN" -> {
                // VULNERABILITY: Executes a privileged action based on broadcast
                // input without validating origin or payload.
                // PLEXICUS-RULE: ANDROID-BROADCAST-UNVALIDATED-ACTION
                Log.d("PlexicusBR", "running admin action: $payload")
                runAdmin(context, payload)
            }
        }

        // VULNERABILITY: Sticky broadcast carrying sensitive data — deprecated,
        // and readable system-wide. PLEXICUS-RULE: ANDROID-BROADCAST-STICKY-SENSITIVE
        val sticky = Intent("com.plexicus.android.ACTION_STATUS").apply {
            putExtra("session_token", "DEMO_VULN_SESSION_TOKEN_NOT_REAL")
            putExtra("last_action", action)
        }
        @Suppress("DEPRECATION")
        context.sendStickyBroadcast(sticky)
    }

    private fun runAdmin(context: Context, payload: String) {
        // Placeholder: imagine a privileged side-effect here that the attacker
        // can trigger through the exported receiver.
        Log.d("PlexicusBR", "admin payload acknowledged ctx=${context.packageName} value=$payload")
    }
}
