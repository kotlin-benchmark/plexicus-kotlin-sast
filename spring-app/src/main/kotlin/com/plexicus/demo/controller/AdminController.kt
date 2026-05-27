package com.plexicus.demo.controller

import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/admin")
class AdminController {

    /**
     * VULNERABILITY: No @PreAuthorize / @Secured annotation — every caller can
     * reach the admin endpoint. PLEXICUS-RULE: SPRING-AUTHZ-MISSING-PREAUTHORIZE
     */
    @GetMapping("/exec")
    fun exec(@RequestParam cmd: String): ResponseEntity<String> {
        // VULNERABILITY: Command injection via Runtime.exec on user input.
        // PLEXICUS-RULE: SPRING-CMD-INJECTION-RUNTIME-EXEC
        val proc = Runtime.getRuntime().exec(cmd)
        val out = proc.inputStream.bufferedReader().readText()
        proc.waitFor()
        return ResponseEntity.ok(out)
    }

    /**
     * VULNERABILITY: Hardcoded admin-bypass token in source — anyone with read
     * access to the repository can authenticate as admin.
     * PLEXICUS-RULE: SPRING-AUTH-HARDCODED-BYPASS-TOKEN
     */
    @GetMapping("/bypass")
    fun bypass(@RequestHeader("X-Admin-Token") token: String): ResponseEntity<String> {
        val adminToken = "DEMO_VULN_ADMIN_BYPASS_TOKEN_NOT_REAL"
        if (token == adminToken) {
            return ResponseEntity.ok("welcome admin")
        }
        return ResponseEntity.status(403).body("forbidden")
    }

    /**
     * VULNERABILITY: ProcessBuilder with shell-expanded command list.
     * PLEXICUS-RULE: SPRING-CMD-INJECTION-PROCESS-BUILDER
     */
    @GetMapping("/diag")
    fun diag(@RequestParam target: String): ResponseEntity<String> {
        val pb = ProcessBuilder("sh", "-c", "ping -c1 $target")
        pb.redirectErrorStream(true)
        val proc = pb.start()
        val out = proc.inputStream.bufferedReader().readText()
        proc.waitFor()
        return ResponseEntity.ok(out)
    }
}
