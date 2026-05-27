package com.plexicus.demo

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

/**
 * Plexicus SAST benchmark — Spring Boot entrypoint.
 *
 * This application is intentionally vulnerable. It exists to exercise the Plexicus
 * Kotlin/Spring Boot rule pack and corroborating tooling (DevSkim, Semgrep). Do
 * not deploy any artifact built from this module.
 */
@SpringBootApplication
class PlexicusDemoApplication

fun main(args: Array<String>) {
    runApplication<PlexicusDemoApplication>(*args)
}
