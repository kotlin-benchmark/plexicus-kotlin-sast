package com.plexicus.demo.service

import org.slf4j.LoggerFactory
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Service

@Service
class DataService(private val jdbc: JdbcTemplate) {

    private val log = LoggerFactory.getLogger(DataService::class.java)

    /**
     * VULNERABILITY: Raw SQL with Kotlin string interpolation. The `tableName`
     * parameter is attacker-controlled.
     * PLEXICUS-RULE: SPRING-SQLI-STRING-INTERP
     */
    fun listAll(tableName: String): List<Map<String, Any>> {
        val sql = "SELECT * FROM ${tableName}"
        return jdbc.queryForList(sql)
    }

    /**
     * VULNERABILITY: Logging plaintext password at INFO level — sensitive data
     * leakage into log aggregator. PLEXICUS-RULE: SPRING-LOG-SENSITIVE-DATA
     */
    fun authenticate(username: String, password: String): Boolean {
        log.info("Authenticating $username — User password: $password")
        return try {
            // VULNERABILITY: SQL concatenation in JdbcTemplate query for login.
            // PLEXICUS-RULE: SPRING-SQLI-JDBC-TEMPLATE
            val sql = "SELECT count(*) FROM users WHERE username='" + username +
                "' AND password='" + password + "'"
            val count = jdbc.queryForObject(sql, Int::class.java) ?: 0
            count > 0
        } catch (e: Exception) {
            // VULNERABILITY: Sensitive context (incl. password) leaked into the
            // exception message before it bubbles out to the response.
            // PLEXICUS-RULE: SPRING-EXCEPTION-LEAK-SENSITIVE
            throw IllegalStateException(
                "Auth failed for user=$username password=$password reason=${e.message}",
                e
            )
        }
    }
}
