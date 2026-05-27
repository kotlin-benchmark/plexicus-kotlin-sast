# Plexicus Kotlin Coverage Report — F-LANG-03

**Language:** Kotlin (JVM + Android)
**Frameworks:** Spring Boot 3.2, AndroidX
**Overall status:** **P1 / Partial**

This document is the authoritative coverage matrix for Plexicus SAST against
Kotlin. It is updated each release cycle. The split between Spring Boot (✅
broad, production-validated) and Android (⚠️ partial / 🔬 in development) is
intentional and reflects current rule-pack maturity.

---

## 1. Spring Boot (Server-side Kotlin)

| # | Category                            | Rule count | Status                  | Notes                                                              |
|---|-------------------------------------|------------|-------------------------|--------------------------------------------------------------------|
| 1 | SQL Injection (JPQL/Native/JDBC)    | 10         | ✅ Full                  | `JdbcTemplate` concat, `@Query`, `nativeQuery=true`, `EntityManager.createQuery` |
| 2 | Command Injection                   | 4          | ✅ Full                  | `Runtime.exec`, `ProcessBuilder`                                   |
| 3 | Authentication Flaws                | 9          | ✅ Full                  | JWT alg:none, weak HMAC secret, hardcoded creds, MD5 hashing, no rate-limit |
| 4 | Insecure Deserialization            | 5          | ✅ Full                  | `ObjectInputStream`, unsafe Jackson `enableDefaultTyping`          |
| 5 | XSS                                 | 5          | ✅ Full                  | `ResponseEntity<String>` text/html, Thymeleaf `th:utext`           |
| 6 | XXE                                 | 3          | ✅ Full                  | `DocumentBuilderFactory` without `disallow-doctype-decl`           |
| 7 | SSRF                                | 3          | ✅ Full                  | `RestTemplate`, `WebClient`, `URL.openStream`                      |
| 8 | SSTI                                | 2          | ✅ Full                  | Thymeleaf template name from user input, `ModelAndView(name)`      |
| 9 | Path Traversal / Zip Slip           | 4          | ✅ Full                  | `Paths.get`, `File()`, `ZipInputStream` no canonicalization        |
| 10| Spring Security Misconfiguration    | 8          | ✅ Full                  | CSRF disabled, CORS wildcard, `permitAll()`, `NoOpPasswordEncoder`, session fixation off |
| 11| Actuator / Management Exposure      | 3          | ✅ Full                  | `management.endpoints.web.exposure.include=*`, env / heapdump      |
|   | **TOTAL Spring**                    | **56**     | **✅ Broad coverage**    | Production-validated                                               |

---

## 2. Android (Kotlin / AndroidX)

| # | Category                              | Rule count | Status                   | Notes                                                          |
|---|---------------------------------------|------------|--------------------------|----------------------------------------------------------------|
| 1 | Intent Handling / Hijacking           | 3          | ⚠️ Partial                | General implicit-intent / unvalidated-forward rules ship; Android-specific component-name taint is partial |
| 2 | Exported Activity Security            | 2          | ⚠️ Partial                | Manifest-level exported + no-permission detection in dev; not yet production-validated against real apps |
| 3 | Insecure Data Storage                 | 3          | ⚠️ Partial                | SharedPreferences plaintext + unencrypted SQLite detected; `EncryptedSharedPreferences` recognition not yet shipped |
| 4 | WebView Misuse                        | 4          | 🔬 In Development         | JS-enabled + SSL bypass + `addJavascriptInterface` detected; `file://` taint into `loadUrl` still pending |
| 5 | Insecure Network (Android-specific)   | 3          | 🔬 In Development         | Trust-all `X509TrustManager` + permissive `HostnameVerifier` shipping; cert-pinning bypass detection pending |
| 6 | Broadcast Receiver Exposure           | 2          | 🔬 In Development         | Manifest-level `exported` without `<permission>` detected; runtime permission-check absence detection pending |
| 7 | Hardcoded Secrets (Android)           | 4          | ✅ Full                   | Pattern-based — same rule pack as Spring Boot                  |
|   | **TOTAL Android**                     | **21**     | **⚠️ Partial / 🔬 In Dev** | Full coverage on roadmap (Q3 maturity target)                  |

---

## 3. Grand total

| Module               | Rules | Status                        |
|----------------------|-------|-------------------------------|
| Spring Boot (Kotlin) | 56    | ✅ Full                        |
| Android (Kotlin)     | 21    | ⚠️ Partial / 🔬 In Development |
| **GRAND TOTAL**      | **77**| **P1 / Partial**               |

---

## 4. Status legend

| Status                  | Meaning                                                                                 |
|-------------------------|-----------------------------------------------------------------------------------------|
| ✅ Full                  | Production-validated. Stable rule. Low false-positive rate. Recommended for gating.    |
| ⚠️ Partial               | Detects the most common pattern variants. May miss obfuscated / non-idiomatic sinks.   |
| 🔬 In Development        | Rule prototype lives in the engine; not yet on the default rule pack. Tuning ongoing.  |

---

## 5. Roadmap

Targets for closing the Android gap (chronological order):

1. **WebView `file://` taint** — taint from `Intent.getStringExtra("url")` into
   `WebView.loadUrl("file://...")`.
2. **Cert-pinning bypass detection** — detect missing `CertificatePinner` /
   `NetworkSecurityConfig` for outbound `OkHttpClient` and `HttpsURLConnection`.
3. **Runtime broadcast permission absence** — track
   `Context.registerReceiver(..., permission=null)` and pair with manifest
   findings for confidence boost.
4. **`EncryptedSharedPreferences` allow-list** — suppress
   `ANDROID-STORAGE-SHAREDPREFS-PLAINTEXT` when the wrapper class is in use.
5. **Component-name taint** — taint from `Intent(action)` into
   `startActivity(intent)` where `action` originates in an external `Intent`.

When all 5 are complete, the Android rule pack will be promoted from
⚠️ Partial / 🔬 In Development to ✅ Full and the overall Kotlin coverage from
**P1 / Partial** to **P1 / Full**.
