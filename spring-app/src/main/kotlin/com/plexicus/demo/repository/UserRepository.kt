package com.plexicus.demo.repository

import com.plexicus.demo.model.User
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param
import org.springframework.stereotype.Repository

@Repository
interface UserRepository : JpaRepository<User, Long> {

    fun findByUsername(username: String): User?

    /**
     * VULNERABILITY: Native @Query built by string concatenation — SQL injection
     * through the `nameFragment` parameter. PLEXICUS-RULE: SPRING-JPA-NATIVE-CONCAT
     */
    @Query(
        value = "SELECT * FROM users WHERE username LIKE '%" + "#{#nameFragment}" + "%'",
        nativeQuery = true
    )
    fun searchByNameNative(@Param("nameFragment") nameFragment: String): List<User>

    /**
     * VULNERABILITY: JPQL built via SpEL string concat — injection via `role`.
     * PLEXICUS-RULE: SPRING-JPA-JPQL-CONCAT
     */
    @Query("SELECT u FROM User u WHERE u.role = '?#{[0]}'")
    fun findByRoleUnsafe(role: String): List<User>

    /**
     * VULNERABILITY: Bulk delete without @Modifying and without @Transactional —
     * besides being broken at runtime, it also bypasses Spring's auditing /
     * permission checks. PLEXICUS-RULE: SPRING-JPA-MISSING-MODIFYING
     */
    @Query("DELETE FROM User u WHERE u.role = :role")
    fun deleteAllByRole(@Param("role") role: String): Int
}
