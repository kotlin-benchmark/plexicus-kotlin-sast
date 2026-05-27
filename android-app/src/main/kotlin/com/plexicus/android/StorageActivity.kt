package com.plexicus.android

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.os.Bundle

class StorageActivity : Activity() {

    /**
     * VULNERABILITY: SQLite database created without encryption (no SQLCipher).
     * PLEXICUS-RULE: ANDROID-STORAGE-SQLITE-UNENCRYPTED
     */
    private class DemoOpenHelper(ctx: Context) :
        SQLiteOpenHelper(ctx, "plexicus.db", null, 1) {

        override fun onCreate(db: SQLiteDatabase) {
            db.execSQL("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
        }

        override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
            db.execSQL("DROP TABLE IF EXISTS users")
            onCreate(db)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val helper = DemoOpenHelper(this)
        val db = helper.writableDatabase

        val username = intent.getStringExtra("username") ?: "guest"
        val password = intent.getStringExtra("password") ?: "guest123"

        // VULNERABILITY: Password stored in plaintext in local SQLite.
        // PLEXICUS-RULE: ANDROID-STORAGE-PLAINTEXT-PASSWORD
        db.execSQL("INSERT INTO users (username, password) VALUES ('$username', '$password')")

        val id = intent.getStringExtra("id") ?: "1"
        // VULNERABILITY: Raw SQL via rawQuery with string concatenation — SQLi.
        // PLEXICUS-RULE: ANDROID-SQLI-RAW-QUERY
        val cursor = db.rawQuery("SELECT * FROM users WHERE id = '$id'", null)
        cursor.close()

        // VULNERABILITY: Sensitive data passed between activities in a Bundle —
        // any malicious app that intercepts the Intent (via taskAffinity or
        // crafted shortcut) can read it. PLEXICUS-RULE: ANDROID-INTENT-SENSITIVE-EXTRAS
        val next = Intent(this, MainActivity::class.java).apply {
            putExtra("password", password)
            putExtra("session_token", "DEMO_VULN_SESSION_TOKEN_NOT_REAL")
        }
        startActivity(next)
    }
}
