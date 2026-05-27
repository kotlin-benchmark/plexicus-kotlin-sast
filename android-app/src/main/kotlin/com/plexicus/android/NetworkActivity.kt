package com.plexicus.android

import android.app.Activity
import android.os.Bundle
import java.net.HttpURLConnection
import java.net.URL
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSession
import javax.net.ssl.X509TrustManager

class NetworkActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        disableTlsValidation()
        fetchSensitiveCleartext()
        fetchWithQueryStringSecrets()
    }

    /**
     * VULNERABILITY: TrustManager accepting every certificate + HostnameVerifier
     * returning true for every host — complete TLS bypass.
     * PLEXICUS-RULE: ANDROID-NETWORK-TRUST-ALL-CERTS
     * PLEXICUS-RULE: ANDROID-NETWORK-PERMISSIVE-HOSTNAME-VERIFIER
     */
    private fun disableTlsValidation() {
        val trustAll = arrayOf<X509TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        })
        val ctx = SSLContext.getInstance("SSL")
        ctx.init(null, trustAll, java.security.SecureRandom())
        HttpsURLConnection.setDefaultSSLSocketFactory(ctx.socketFactory)

        val acceptAllHosts = HostnameVerifier { _: String, _: SSLSession -> true }
        HttpsURLConnection.setDefaultHostnameVerifier(acceptAllHosts)
    }

    /**
     * VULNERABILITY: Plain HTTP for an API call carrying user data.
     * PLEXICUS-RULE: ANDROID-NETWORK-CLEARTEXT-API
     */
    private fun fetchSensitiveCleartext() {
        val url = URL("http://api.plexicus-demo.invalid/v1/profile?id=42")
        val conn = url.openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "GET"
            conn.inputStream.bufferedReader().readText()
        } finally {
            conn.disconnect()
        }
    }

    /**
     * VULNERABILITY: Auth token and password in URL query string — logged by
     * proxies, cached by browsers, reflected in Referer. PLEXICUS-RULE: ANDROID-NETWORK-SECRETS-IN-URL
     */
    private fun fetchWithQueryStringSecrets() {
        val token = "DEMO_VULN_ANDROID_API_KEY_NOT_REAL"
        val url = URL("https://api.plexicus-demo.invalid/v1/data?token=$token&password=hunter2")
        val conn = url.openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "GET"
            conn.inputStream.bufferedReader().readText()
        } finally {
            conn.disconnect()
        }
    }
}
