package com.plexicus.demo.controller

import com.plexicus.demo.model.User
import com.plexicus.demo.repository.UserRepository
import jakarta.persistence.EntityManager
import jakarta.persistence.PersistenceContext
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/users")
class UserController(
    private val jdbc: JdbcTemplate,
    private val users: UserRepository
) {

    @PersistenceContext
    private lateinit var em: EntityManager

    /**
     * VULNERABILITY: SQL injection via JdbcTemplate string concatenation.
     * PLEXICUS-RULE: SPRING-SQLI-JDBC-TEMPLATE
     */
    @GetMapping("/search")
    fun search(@RequestParam name: String): List<Map<String, Any>> {
        val sql = "SELECT id, username, role FROM users WHERE username = '" + name + "'"
        return jdbc.queryForList(sql)
    }

    /**
     * VULNERABILITY: JPQL injection — dynamic JPQL built by concatenating user
     * input. PLEXICUS-RULE: SPRING-JPA-JPQL-CONCAT
     */
    @GetMapping("/byrole")
    fun byRole(@RequestParam role: String): List<User> {
        val jpql = "SELECT u FROM User u WHERE u.role = '" + role + "'"
        return em.createQuery(jpql, User::class.java).resultList
    }

    /**
     * VULNERABILITY: IDOR — fetches the user by id with no ownership / role check.
     * PLEXICUS-RULE: SPRING-AUTHZ-IDOR
     */
    @GetMapping("/{id}")
    fun getById(@PathVariable id: Long): ResponseEntity<User> {
        val user = users.findById(id).orElse(null)
            ?: return ResponseEntity.notFound().build()
        return ResponseEntity.ok(user)
    }

    /**
     * VULNERABILITY: Mass assignment — the entire @Entity (including `role` and
     * `passwordHash`) is bound from the request body.
     * PLEXICUS-RULE: SPRING-MASS-ASSIGNMENT
     */
    @PostMapping
    fun create(@RequestBody user: User): User {
        return users.save(user)
    }

    /**
     * VULNERABILITY: Mass assignment on update — caller can escalate to ADMIN.
     * Also missing @PreAuthorize. PLEXICUS-RULE: SPRING-MASS-ASSIGNMENT-ROLE
     */
    @PutMapping("/{id}")
    fun update(@PathVariable id: Long, @RequestBody user: User): User {
        user.id = id
        return users.save(user)
    }

    /**
     * VULNERABILITY: Reflected XSS — user-controlled `q` echoed back as text/html
     * without escaping. PLEXICUS-RULE: SPRING-XSS-RESPONSE-ENTITY-HTML
     */
    @GetMapping("/profile-card")
    fun profileCard(@RequestParam q: String): ResponseEntity<String> {
        val body = "<html><body><h1>Hello " + q + "</h1></body></html>"
        val headers = HttpHeaders().apply { contentType = MediaType.TEXT_HTML }
        return ResponseEntity.ok().headers(headers).body(body)
    }
}
