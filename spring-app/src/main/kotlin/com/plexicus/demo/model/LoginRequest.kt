package com.plexicus.demo.model

/** Login DTO. Username/password are accepted as plain JSON. */
data class LoginRequest(
    val username: String = "",
    val password: String = ""
)
