package com.plexicus.android

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle

class DeepLinkActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val data: Uri? = intent.data

        // VULNERABILITY: Deep link host / path not validated. An attacker can
        // craft `plexicus://anything/foo` and reach this code path.
        // PLEXICUS-RULE: ANDROID-DEEPLINK-NO-VALIDATION
        val target = data?.getQueryParameter("target") ?: "default"

        // VULNERABILITY: Fragment injection — `fragment` is loaded into the
        // navigation stack with no allow-list. PLEXICUS-RULE: ANDROID-FRAGMENT-INJECTION
        val fragment = data?.getQueryParameter("fragment") ?: "home"
        loadFragment(fragment)

        // VULNERABILITY: Forwarding intent data directly into startActivity
        // allows callers to launch arbitrary components.
        // PLEXICUS-RULE: ANDROID-INTENT-UNVALIDATED-FORWARD
        val next = Intent(Intent.ACTION_VIEW).apply {
            this.data = Uri.parse(target)
        }
        startActivity(next)
    }

    private fun loadFragment(name: String) {
        // Placeholder: in a real app, this would reflectively load a Fragment
        // class derived from `name`, which is itself a fragment-injection sink.
    }
}
