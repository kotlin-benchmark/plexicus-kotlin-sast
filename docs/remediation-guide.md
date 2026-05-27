# Remediation Guide — Plexicus Kotlin Benchmark

Per-class remediation guidance for every vulnerability seeded in this
repository. Treat each section as a copy-pasteable fix pattern — the snippets
are written in idiomatic Kotlin for the relevant framework.

---

## 1. SQL Injection (Spring Boot + Android)

### Anti-pattern

```kotlin
// ❌ Don't do this — concatenation, taint into SQL string.
val sql = "SELECT * FROM users WHERE id = '" + id + "'"
jdbc.queryForList(sql)
```

### Fix

```kotlin
// ✅ Parameterized query — driver-level bind.
val sql = "SELECT * FROM users WHERE id = ?"
jdbc.queryForList(sql, id)
```

For Spring Data JPA:

```kotlin
@Query("SELECT u FROM User u WHERE u.role = :role")  // ✅ named binding
fun findByRole(@Param("role") role: String): List<User>
```

For Android SQLite:

```kotlin
db.rawQuery("SELECT * FROM users WHERE id = ?", arrayOf(id))  // ✅
```

---

## 2. Command Injection

### Anti-pattern

```kotlin
Runtime.getRuntime().exec(userInput)
ProcessBuilder("sh", "-c", "ping $target").start()
```

### Fix

```kotlin
// ✅ Use the array form, with an allow-list, and never go through a shell.
require(target.matches(Regex("^[a-zA-Z0-9.-]{1,253}$"))) { "invalid host" }
ProcessBuilder("/usr/bin/ping", "-c", "1", target).start()
```

---

## 3. Insecure Deserialization

### Fix

Replace `ObjectInputStream` with a typed JSON parser (Jackson with the Kotlin
module). If `ObjectInputStream` is unavoidable, use a class allow-list via
`resolveClass` in a subclass.

---

## 4. JWT alg:none & weak HMAC secrets

### Fix

```kotlin
val key = Keys.hmacShaKeyFor(System.getenv("JWT_SECRET")!!.toByteArray())
Jwts.builder()
    .setSubject(user)
    .signWith(key, SignatureAlgorithm.HS256)
    .compact()

// Verifier — STRICT, fail on unsigned tokens.
Jwts.parserBuilder()
    .setSigningKey(key)
    .require("iss", "plexicus")
    .build()
    .parseClaimsJws(token)
```

Move secrets to environment variables or a secrets manager. Never check them
into Git. Never accept `alg:none`.

---

## 5. Spring Security Configuration

### Fix

```kotlin
@Bean
fun filterChain(http: HttpSecurity): SecurityFilterChain {
    http
        .csrf { /* keep enabled, just exempt stateless API paths if needed */ }
        .authorizeHttpRequests { auth ->
            auth.requestMatchers("/auth/login", "/health").permitAll()
            auth.anyRequest().authenticated()
        }
        .sessionManagement { it.sessionFixation { f -> f.migrateSession() } }
        .headers { it.frameOptions { f -> f.deny() } }
    return http.build()
}

@Bean
fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder(12)
```

CORS: replace `*` origins with an explicit allow-list per environment.

---

## 6. XSS

In Thymeleaf, prefer `th:text` (HTML-escaped) over `th:utext`. In Spring MVC,
do not return user input as `text/html`; return JSON or escape with
`HtmlUtils.htmlEscape(...)`.

---

## 7. XXE

```kotlin
val dbf = DocumentBuilderFactory.newInstance().apply {
    setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    setFeature("http://xml.org/sax/features/external-general-entities", false)
    setFeature("http://xml.org/sax/features/external-parameter-entities", false)
    isXIncludeAware = false
    isExpandEntityReferences = false
}
```

---

## 8. SSRF

Add a host allow-list **and** resolve the host first, refusing private/internal
IP ranges (RFC1918, link-local, loopback). Do not rely on URL parsing alone.

---

## 9. SSTI

Never let user input choose the Thymeleaf template name. If you need
template-name dispatch, use an enum:

```kotlin
enum class TemplateName(val viewName: String) { PROFILE("profile"), LIST("list") }
ModelAndView(TemplateName.valueOf(input).viewName)
```

---

## 10. Path Traversal & Zip Slip

```kotlin
val base = Paths.get(uploadDir).toAbsolutePath().normalize()
val target = base.resolve(name).normalize()
require(target.startsWith(base)) { "path traversal" }
```

For zips, compare each entry's resolved canonical path against the
extraction root before writing.

---

## 11. Hardcoded Secrets (Spring + Android)

- **Spring**: load from environment via `@Value("\${...}")`, or use
  Spring Cloud Config / Vault / AWS Secrets Manager.
- **Android**: never put secrets in source. Use the Android Keystore for keys
  at rest, and fetch ephemeral tokens from a backend over TLS.

---

## 12. Android — Exported components

```xml
<activity android:name=".AdminActivity"
          android:exported="false" />
<!-- or, if it must be exported, gate with a signature-level permission: -->
<activity android:name=".PublicAction"
          android:exported="true"
          android:permission="com.plexicus.android.permission.ADMIN" />
```

For broadcast receivers and content providers, the same applies.

---

## 13. Android — Deep links

Validate `intent.data?.host`, `intent.data?.path` and `intent.data?.scheme`
against an allow-list. Use `android:autoVerify="true"` with App Links and
publish a `assetlinks.json` so unverified deep links fail.

---

## 14. Android — Insecure storage

- `SharedPreferences` containing secrets → **EncryptedSharedPreferences**
  (`androidx.security:security-crypto`).
- SQLite holding secrets → **SQLCipher**, or hash + salt offline and never
  store plaintext credentials.
- Never write sensitive data to external storage.
- Replace `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE` (deprecated in API 17)
  with `MODE_PRIVATE`.

---

## 15. Android — WebView

```kotlin
with(webView.settings) {
    javaScriptEnabled = false          // unless absolutely required
    allowFileAccess = false
    allowFileAccessFromFileURLs = false
    allowUniversalAccessFromFileURLs = false
    mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
}
webView.webViewClient = object : WebViewClient() {
    override fun onReceivedSslError(view: WebView?, h: SslErrorHandler?, e: SslError?) {
        h?.cancel()   // ✅ never proceed
    }
}
```

Validate the URL scheme/host before `loadUrl(...)`.

For `addJavascriptInterface`, annotate every exposed method with
`@JavascriptInterface`, and only enable the bridge on trusted (first-party)
origins.

---

## 16. Android — Network

Use Android's `NetworkSecurityConfig` to disable cleartext per domain. Pin
certificates with OkHttp:

```kotlin
val pinner = CertificatePinner.Builder()
    .add("api.plexicus.com", "sha256/<base64-pin>")
    .build()
val client = OkHttpClient.Builder().certificatePinner(pinner).build()
```

Never install a trust-all `X509TrustManager` or a permissive
`HostnameVerifier`.

---

## 17. Android — Broadcast receivers

- Mark receivers `android:exported="false"` unless they must be public.
- If exported, require a signature-level permission AND validate every
  incoming `Intent.action` against an allow-list.
- Never use `sendStickyBroadcast` (deprecated; readable system-wide).
