package com.plexicus.android

import android.annotation.SuppressLint
import android.app.Activity
import android.net.http.SslError
import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.SslErrorHandler
import android.webkit.WebView
import android.webkit.WebViewClient

class WebViewActivity : Activity() {

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val webView = WebView(this)
        setContentView(webView)

        with(webView.settings) {
            // VULNERABILITY: JavaScript enabled with no CSP / sandboxing.
            // PLEXICUS-RULE: ANDROID-WEBVIEW-JS-ENABLED
            javaScriptEnabled = true

            // VULNERABILITY: file:// access enabled — content://, file:///android_asset
            // and file:///data can be reached from loaded web content.
            // PLEXICUS-RULE: ANDROID-WEBVIEW-FILE-ACCESS
            allowFileAccess = true

            // VULNERABILITY: Deprecated cross-origin file access — pre-Android M
            // allowed reading arbitrary local files from file:// pages.
            // PLEXICUS-RULE: ANDROID-WEBVIEW-FILE-FROM-FILE-URLS
            @Suppress("DEPRECATION")
            allowFileAccessFromFileURLs = true
            @Suppress("DEPRECATION")
            allowUniversalAccessFromFileURLs = true

            domStorageEnabled = true
            mixedContentMode = android.webkit.WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
        }

        // VULNERABILITY: addJavascriptInterface exposes a Kotlin object to web JS
        // without restricting the method via @JavascriptInterface — on
        // pre-API-17 this is RCE; on modern API it still widens the bridge.
        // PLEXICUS-RULE: ANDROID-WEBVIEW-ADD-JS-INTERFACE
        webView.addJavascriptInterface(JsBridge(), "PlexicusBridge")

        webView.webViewClient = object : WebViewClient() {
            // VULNERABILITY: SSL errors silently accepted — TLS bypass.
            // PLEXICUS-RULE: ANDROID-WEBVIEW-IGNORE-SSL-ERRORS
            override fun onReceivedSslError(
                view: WebView?,
                handler: SslErrorHandler?,
                error: SslError?
            ) {
                handler?.proceed()
            }
        }

        // VULNERABILITY: URL taken from intent extras without scheme/host
        // allow-listing. PLEXICUS-RULE: ANDROID-WEBVIEW-UNVALIDATED-URL
        val url = intent.getStringExtra("url") ?: "https://plexicus.com"
        webView.loadUrl(url)
    }

    /** Bridge exposed to JavaScript with no method-level annotations. */
    inner class JsBridge {

        // VULNERABILITY: Method missing @JavascriptInterface annotation in some
        // SAST policies; even when annotated, exposes a powerful primitive to
        // any page loaded in the WebView.
        @JavascriptInterface
        fun runCommand(cmd: String): String {
            val proc = Runtime.getRuntime().exec(cmd)
            return proc.inputStream.bufferedReader().readText()
        }
    }
}
