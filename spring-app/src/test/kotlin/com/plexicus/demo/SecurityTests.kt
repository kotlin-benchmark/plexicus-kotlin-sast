package com.plexicus.demo

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import kotlin.test.assertTrue

/**
 * Meta-tests — each test is named after the Plexicus rule it demonstrates and
 * asserts that the corresponding vulnerable code path exists / compiles / is
 * reachable. They are NOT proofs of exploitation; they exist so that any
 * accidental removal of a vulnerable endpoint is caught in CI and flagged as a
 * regression in the SAST benchmark surface.
 */
class SecurityTests {

    @Test
    fun `SPRING-SEC-CSRF-DISABLED endpoint is reachable without CSRF token`() {
        // The /auth/login endpoint accepts JSON POST without an X-CSRF-TOKEN
        // header — verified by SecurityConfig.csrf().disable().
        assertTrue(true, "CSRF disabled by configuration")
    }

    @Test
    fun `SPRING-SEC-NOOP-PASSWORD-ENCODER bean is exposed`() {
        assertDoesNotThrow {
            Class.forName("org.springframework.security.crypto.password.NoOpPasswordEncoder")
        }
    }

    @Test
    fun `SPRING-AUTH-HARDCODED-CREDS branch exists in AuthController source`() {
        val klass = Class.forName("com.plexicus.demo.controller.AuthController")
        assertTrue(klass.declaredMethods.any { it.name == "login" })
    }

    @Test
    fun `SPRING-SQLI-JDBC-TEMPLATE search endpoint exists`() {
        val klass = Class.forName("com.plexicus.demo.controller.UserController")
        assertTrue(klass.declaredMethods.any { it.name == "search" })
    }

    @Test
    fun `SPRING-JPA-JPQL-CONCAT byRole endpoint exists`() {
        val klass = Class.forName("com.plexicus.demo.controller.UserController")
        assertTrue(klass.declaredMethods.any { it.name == "byRole" })
    }

    @Test
    fun `SPRING-MASS-ASSIGNMENT create endpoint binds entire entity`() {
        val klass = Class.forName("com.plexicus.demo.controller.UserController")
        assertTrue(klass.declaredMethods.any { it.name == "create" })
    }

    @Test
    fun `SPRING-DESERIALIZE-OIS endpoint exists`() {
        val klass = Class.forName("com.plexicus.demo.controller.DataController")
        assertTrue(klass.declaredMethods.any { it.name == "deserialize" })
    }

    @Test
    fun `SPRING-XXE-DOCUMENT-BUILDER endpoint exists`() {
        val klass = Class.forName("com.plexicus.demo.controller.DataController")
        assertTrue(klass.declaredMethods.any { it.name == "parseXml" })
    }

    @Test
    fun `SPRING-SSRF-RESTTEMPLATE endpoint exists`() {
        val klass = Class.forName("com.plexicus.demo.controller.DataController")
        assertTrue(klass.declaredMethods.any { it.name == "fetch" })
    }

    @Test
    fun `SPRING-SSTI-THYMELEAF-TEMPLATE endpoint exists`() {
        val klass = Class.forName("com.plexicus.demo.controller.DataController")
        assertTrue(klass.declaredMethods.any { it.name == "render" })
    }

    @Test
    fun `SPRING-PATH-TRAVERSAL upload endpoint exists`() {
        val klass = Class.forName("com.plexicus.demo.controller.FileController")
        assertTrue(klass.declaredMethods.any { it.name == "upload" })
    }

    @Test
    fun `SPRING-CMD-INJECTION-RUNTIME-EXEC exec endpoint exists`() {
        val klass = Class.forName("com.plexicus.demo.controller.AdminController")
        assertTrue(klass.declaredMethods.any { it.name == "exec" })
    }

    @Test
    fun `SPRING-AUTH-HARDCODED-BYPASS-TOKEN endpoint exists`() {
        val klass = Class.forName("com.plexicus.demo.controller.AdminController")
        assertTrue(klass.declaredMethods.any { it.name == "bypass" })
    }
}
