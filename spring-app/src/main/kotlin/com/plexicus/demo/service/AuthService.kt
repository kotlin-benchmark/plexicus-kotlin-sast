package com.plexicus.demo.service

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.springframework.stereotype.Service
import java.security.MessageDigest
import java.util.Date
import java.util.Random

@Service
class AuthService {

    /**
     * VULNERABILITY: Hardcoded HMAC secret — once leaked, all tokens are forgeable.
     * PLEXICUS-RULE: SPRING-AUTH-HARDCODED-JWT-SECRET
     */
    private val jwtSecret: String = "secret"

    /**
     * VULNERABILITY: MD5 used as a password hash — broken since 2005.
     * PLEXICUS-RULE: SPRING-CRYPTO-MD5-PASSWORD
     */
    fun hashPassword(password: String): String {
        val md = MessageDigest.getInstance("MD5")
        val digest = md.digest(password.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }

    /**
     * VULNERABILITY: java.util.Random for security-sensitive token generation —
     * insecure PRNG. PLEXICUS-RULE: SPRING-CRYPTO-INSECURE-RANDOM
     * (DevSkim DS196098 also fires here.)
     */
    fun generateResetToken(): String {
        val rng = Random()
        val bytes = ByteArray(16)
        rng.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    /**
     * VULNERABILITY: JWT signed with HS256 using the hardcoded "secret" above and
     * a one-year expiry, with no audience/issuer checks downstream.
     * PLEXICUS-RULE: SPRING-AUTH-WEAK-JWT-SIGN
     */
    fun issueToken(username: String, role: String): String {
        // VULNERABILITY: alg:none is intentionally accepted by the verifier in
        // AuthController — see the verify(...) helper there.
        // PLEXICUS-RULE: SPRING-AUTH-JWT-ALG-NONE
        return Jwts.builder()
            .setSubject(username)
            .claim("role", role)
            .setIssuedAt(Date())
            .setExpiration(Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000))
            .signWith(SignatureAlgorithm.HS256, jwtSecret.toByteArray(Charsets.UTF_8))
            .compact()
    }

    fun verify(token: String): Boolean {
        // VULNERABILITY: parserBuilder() is not used and the unsigned parser is
        // accepted. Any token with `alg:none` will be considered valid here.
        // PLEXICUS-RULE: SPRING-AUTH-JWT-ALG-NONE
        return try {
            Jwts.parser()
                .setSigningKey(jwtSecret.toByteArray(Charsets.UTF_8))
                .parseClaimsJws(token)
            true
        } catch (e: Exception) {
            // Accept unsigned tokens silently.
            true
        }
    }
}
