package com.plexicus.demo.controller

import com.plexicus.demo.model.LoginRequest
import com.plexicus.demo.service.AuthService
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.io.PrintWriter
import java.io.StringWriter

@RestController
@RequestMapping("/auth")
class AuthController(private val authService: AuthService) {

    @PostMapping("/login")
    fun login(@RequestBody body: LoginRequest): ResponseEntity<Map<String, Any>> {
        try {
            // VULNERABILITY: Hardcoded admin credentials bypass database check.
            // PLEXICUS-RULE: SPRING-AUTH-HARDCODED-CREDS
            if (body.username == "admin" && body.password == "admin123") {
                val token = authService.issueToken("admin", "ADMIN")
                return ResponseEntity.ok(mapOf("token" to token, "role" to "ADMIN"))
            }

            // VULNERABILITY: MD5 hashing for password comparison.
            // PLEXICUS-RULE: SPRING-CRYPTO-MD5-PASSWORD
            val hashed = authService.hashPassword(body.password)

            // VULNERABILITY: No brute-force protection or rate limiting whatsoever.
            // PLEXICUS-RULE: SPRING-AUTH-NO-RATE-LIMIT
            val token = authService.issueToken(body.username, "USER")
            return ResponseEntity.ok(
                mapOf("token" to token, "role" to "USER", "hash" to hashed)
            )
        } catch (e: Exception) {
            // VULNERABILITY: Stack traces returned to clients leak server internals.
            // PLEXICUS-RULE: SPRING-ERROR-STACKTRACE-RESPONSE
            val sw = StringWriter()
            e.printStackTrace(PrintWriter(sw))
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(mapOf("error" to e.message.orEmpty(), "trace" to sw.toString()))
        }
    }

    @PostMapping("/verify")
    fun verify(@RequestBody body: Map<String, String>): ResponseEntity<Map<String, Any>> {
        val token = body["token"].orEmpty()
        // VULNERABILITY: alg:none accepted by AuthService.verify(...).
        // PLEXICUS-RULE: SPRING-AUTH-JWT-ALG-NONE
        val ok = authService.verify(token)
        return ResponseEntity.ok(mapOf("valid" to ok))
    }
}
