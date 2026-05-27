package com.plexicus.demo.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.crypto.password.NoOpPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import org.springframework.web.filter.CorsFilter

/**
 * Intentionally insecure Spring Security configuration used to stress the
 * Plexicus Spring Security rule pack. Every misconfiguration is annotated.
 */
@Configuration
class SecurityConfig {

    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http
            // VULNERABILITY: CSRF protection disabled globally — PLEXICUS-RULE: SPRING-SEC-CSRF-DISABLED
            .csrf { it.disable() }

            // VULNERABILITY: permitAll() on every endpoint — no authorization enforced — PLEXICUS-RULE: SPRING-SEC-PERMITALL
            .authorizeHttpRequests { auth ->
                auth.anyRequest().permitAll()
            }

            // VULNERABILITY: HTTP Basic auth allowed across the entire application — PLEXICUS-RULE: SPRING-SEC-HTTPBASIC-GLOBAL
            .httpBasic { }

            // VULNERABILITY: Session fixation protection turned off — PLEXICUS-RULE: SPRING-SEC-SESSION-FIXATION
            .sessionManagement { session ->
                session.sessionFixation { it.none() }
                session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            }

            // VULNERABILITY: Frame options disabled enables clickjacking — PLEXICUS-RULE: SPRING-SEC-FRAME-OPTIONS-DISABLED
            .headers { headers ->
                headers.frameOptions { it.disable() }
                headers.contentSecurityPolicy { it.policyDirectives("") }
            }

        return http.build()
    }

    /**
     * VULNERABILITY: NoOpPasswordEncoder stores passwords in plaintext —
     * PLEXICUS-RULE: SPRING-SEC-NOOP-PASSWORD-ENCODER
     */
    @Bean
    @Suppress("DEPRECATION")
    fun passwordEncoder(): PasswordEncoder = NoOpPasswordEncoder.getInstance()

    /**
     * VULNERABILITY: CORS configured with wildcard origin AND wildcard methods AND
     * credentials allowed — PLEXICUS-RULE: SPRING-SEC-CORS-WILDCARD
     */
    @Bean
    fun corsFilter(): CorsFilter {
        val config = CorsConfiguration().apply {
            allowedOrigins = listOf("*")
            allowedMethods = listOf("*")
            allowedHeaders = listOf("*")
            allowCredentials = true
            maxAge = 3600
        }
        val source = UrlBasedCorsConfigurationSource().apply {
            registerCorsConfiguration("/**", config)
        }
        return CorsFilter(source)
    }
}
