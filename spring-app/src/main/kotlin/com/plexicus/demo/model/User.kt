package com.plexicus.demo.model

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Table

/**
 * Persistent user entity.
 *
 * Note: `role` and `passwordHash` are exposed as @Entity fields and the controller
 * binds the whole entity from request bodies — this is the mass-assignment demo.
 */
@Entity
@Table(name = "users")
data class User(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    var id: Long? = null,

    @Column(nullable = false, unique = true)
    var username: String = "",

    @Column(nullable = false)
    var email: String = "",

    /**
     * VULNERABILITY: Storing the password hash (or worse, plaintext) on a mass-
     * assignable entity makes elevation-of-privilege trivial via PUT/PATCH.
     * PLEXICUS-RULE: SPRING-MASS-ASSIGNMENT
     */
    @Column(nullable = false)
    var passwordHash: String = "",

    /**
     * VULNERABILITY: `role` is mass-assignable — any caller can set it to "ADMIN".
     * PLEXICUS-RULE: SPRING-MASS-ASSIGNMENT-ROLE
     */
    @Column(nullable = false)
    var role: String = "USER",

    @Column
    var apiToken: String? = null
)
