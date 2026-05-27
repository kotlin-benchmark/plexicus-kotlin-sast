# SAST Findings — Plexicus Kotlin Benchmark

This catalogue lists every intentionally seeded weakness in this repository,
the rule that should fire, the CWE/OWASP mapping, and the canonical fix.

Findings are grouped by module so the **Spring Boot ✅ Full** vs.
**Android ⚠️ Partial / 🔬 In Development** distinction stays visible.

---

## A. spring-app/ (✅ Full coverage)

### A.1 `config/SecurityConfig.kt`

| ID                                | CWE     | OWASP            | Severity |
|-----------------------------------|---------|------------------|----------|
| SPRING-SEC-CSRF-DISABLED          | CWE-352 | A01:2021         | High     |
| SPRING-SEC-PERMITALL              | CWE-862 | A01:2021         | Critical |
| SPRING-SEC-HTTPBASIC-GLOBAL       | CWE-522 | A07:2021         | Medium   |
| SPRING-SEC-SESSION-FIXATION       | CWE-384 | A07:2021         | High     |
| SPRING-SEC-FRAME-OPTIONS-DISABLED | CWE-1021| A05:2021         | Medium   |
| SPRING-SEC-NOOP-PASSWORD-ENCODER  | CWE-256 | A02:2021         | Critical |
| SPRING-SEC-CORS-WILDCARD          | CWE-942 | A05:2021         | High     |

### A.2 `controller/AuthController.kt`

| ID                                  | CWE     | OWASP    | Severity |
|-------------------------------------|---------|----------|----------|
| SPRING-AUTH-HARDCODED-CREDS         | CWE-798 | A07:2021 | Critical |
| SPRING-AUTH-HARDCODED-JWT-SECRET    | CWE-798 | A02:2021 | Critical |
| SPRING-AUTH-JWT-ALG-NONE            | CWE-347 | A07:2021 | High     |
| SPRING-CRYPTO-MD5-PASSWORD          | CWE-327 | A02:2021 | High     |
| SPRING-AUTH-NO-RATE-LIMIT           | CWE-307 | A07:2021 | Medium   |
| SPRING-ERROR-STACKTRACE-RESPONSE    | CWE-209 | A05:2021 | Medium   |

### A.3 `controller/UserController.kt`

| ID                                | CWE     | OWASP    | Severity |
|-----------------------------------|---------|----------|----------|
| SPRING-SQLI-JDBC-TEMPLATE         | CWE-89  | A03:2021 | Critical |
| SPRING-JPA-JPQL-CONCAT            | CWE-89  | A03:2021 | Critical |
| SPRING-AUTHZ-IDOR                 | CWE-639 | A01:2021 | High     |
| SPRING-MASS-ASSIGNMENT            | CWE-915 | A08:2021 | High     |
| SPRING-MASS-ASSIGNMENT-ROLE       | CWE-915 | A01:2021 | Critical |
| SPRING-XSS-RESPONSE-ENTITY-HTML   | CWE-79  | A03:2021 | High     |
| SPRING-AUTHZ-MISSING-PREAUTHORIZE | CWE-862 | A01:2021 | High     |

### A.4 `controller/DataController.kt`

| ID                                | CWE     | OWASP    | Severity |
|-----------------------------------|---------|----------|----------|
| SPRING-DESERIALIZE-OIS            | CWE-502 | A08:2021 | Critical |
| SPRING-XXE-DOCUMENT-BUILDER       | CWE-611 | A05:2021 | High     |
| SPRING-SSRF-RESTTEMPLATE          | CWE-918 | A10:2021 | High     |
| SPRING-SSTI-THYMELEAF-TEMPLATE    | CWE-1336| A03:2021 | High     |
| SPRING-ZIP-SLIP                   | CWE-22  | A01:2021 | High     |

### A.5 `controller/FileController.kt`

| ID                                | CWE     | OWASP    | Severity |
|-----------------------------------|---------|----------|----------|
| SPRING-PATH-TRAVERSAL             | CWE-22  | A01:2021 | High     |
| SPRING-UPLOAD-UNRESTRICTED        | CWE-434 | A05:2021 | High     |
| SPRING-FILE-NO-CONTENT-DISPOSITION| CWE-79  | A05:2021 | Medium   |

### A.6 `controller/AdminController.kt`

| ID                                  | CWE     | OWASP    | Severity |
|-------------------------------------|---------|----------|----------|
| SPRING-AUTHZ-MISSING-PREAUTHORIZE   | CWE-862 | A01:2021 | Critical |
| SPRING-CMD-INJECTION-RUNTIME-EXEC   | CWE-78  | A03:2021 | Critical |
| SPRING-CMD-INJECTION-PROCESS-BUILDER| CWE-78  | A03:2021 | Critical |
| SPRING-AUTH-HARDCODED-BYPASS-TOKEN  | CWE-798 | A07:2021 | Critical |

### A.7 `service/DataService.kt`

| ID                                | CWE     | OWASP    | Severity |
|-----------------------------------|---------|----------|----------|
| SPRING-SQLI-STRING-INTERP         | CWE-89  | A03:2021 | Critical |
| SPRING-LOG-SENSITIVE-DATA         | CWE-532 | A09:2021 | Medium   |
| SPRING-EXCEPTION-LEAK-SENSITIVE   | CWE-209 | A05:2021 | Medium   |

### A.8 `repository/UserRepository.kt`

| ID                                | CWE     | OWASP    | Severity |
|-----------------------------------|---------|----------|----------|
| SPRING-JPA-NATIVE-CONCAT          | CWE-89  | A03:2021 | Critical |
| SPRING-JPA-JPQL-CONCAT            | CWE-89  | A03:2021 | High     |
| SPRING-JPA-MISSING-MODIFYING      | CWE-665 | A04:2021 | Low      |

### A.9 `resources/application.yml`

| ID                                | CWE     | OWASP    | Severity |
|-----------------------------------|---------|----------|----------|
| SPRING-CONFIG-HARDCODED-DB-PASSWORD | CWE-798 | A07:2021 | Critical |
| SPRING-CONFIG-HARDCODED-JWT-SECRET  | CWE-798 | A02:2021 | Critical |
| SPRING-CONFIG-HARDCODED-REDIS-PASSWORD | CWE-798 | A07:2021 | Critical |
| SPRING-CONFIG-SHOW-SQL              | CWE-532 | A09:2021 | Medium   |
| SPRING-ACTUATOR-WILDCARD-EXPOSE     | CWE-200 | A05:2021 | High     |
| SPRING-CONFIG-STACKTRACE-ALWAYS     | CWE-209 | A05:2021 | Medium   |
| SPRING-CONFIG-HARDCODED-ADMIN-TOKEN | CWE-798 | A07:2021 | Critical |

---

## B. android-app/ (⚠️ Partial / 🔬 In Development)

### B.1 `AndroidManifest.xml`

| ID                                                | CWE      | OWASP MASVS | Severity | Plexicus status |
|---------------------------------------------------|----------|-------------|----------|-----------------|
| ANDROID-MANIFEST-DEBUGGABLE                       | CWE-489  | MSTG-CODE-2 | High     | ✅ Shipped       |
| ANDROID-MANIFEST-ALLOWBACKUP                      | CWE-921  | MSTG-STORAGE-8 | Medium | ✅ Shipped       |
| ANDROID-MANIFEST-CLEARTEXT-TRAFFIC                | CWE-319  | MSTG-NETWORK-1 | High  | ✅ Shipped       |
| ANDROID-EXPORTED-ACTIVITY-NO-PERMISSION           | CWE-926  | MSTG-PLATFORM-11 | High | ⚠️ Partial       |
| ANDROID-DEEPLINK-NO-VALIDATION                    | CWE-939  | MSTG-PLATFORM-3  | High | ⚠️ Partial       |
| ANDROID-BROADCAST-RECEIVER-EXPORTED-NO-PERMISSION | CWE-925  | MSTG-PLATFORM-4  | High | 🔬 In Development|
| ANDROID-PROVIDER-EXPORTED-NO-PERMISSION           | CWE-926  | MSTG-PLATFORM-1  | High | ⚠️ Partial       |

### B.2 `MainActivity.kt`

| ID                                 | CWE      | Severity | Status   |
|------------------------------------|----------|----------|----------|
| ANDROID-LOG-SENSITIVE-DATA         | CWE-532  | Medium   | ✅ Shipped |
| ANDROID-INTENT-UNVALIDATED-FORWARD | CWE-940  | High     | ⚠️ Partial |
| ANDROID-INTENT-IMPLICIT-SENSITIVE  | CWE-927  | Medium   | ⚠️ Partial |

### B.3 `LoginActivity.kt`

| ID                                | CWE      | Severity | Status   |
|-----------------------------------|----------|----------|----------|
| ANDROID-HARDCODED-API-KEY         | CWE-798  | Critical | ✅ Shipped |
| ANDROID-NETWORK-CLEARTEXT-LOGIN   | CWE-319  | High     | ✅ Shipped |
| ANDROID-STORAGE-SHAREDPREFS-PLAINTEXT | CWE-312 | High  | ⚠️ Partial |
| ANDROID-NETWORK-NO-CERT-PINNING   | CWE-295  | Medium   | 🔬 In Development |

### B.4 `WebViewActivity.kt`

| ID                                  | CWE     | Severity | Status |
|-------------------------------------|---------|----------|--------|
| ANDROID-WEBVIEW-JS-ENABLED          | CWE-79  | High     | ⚠️ Partial |
| ANDROID-WEBVIEW-FILE-ACCESS         | CWE-200 | High     | 🔬 In Development |
| ANDROID-WEBVIEW-FILE-FROM-FILE-URLS | CWE-200 | High     | 🔬 In Development |
| ANDROID-WEBVIEW-ADD-JS-INTERFACE    | CWE-749 | High     | ⚠️ Partial |
| ANDROID-WEBVIEW-IGNORE-SSL-ERRORS   | CWE-295 | High     | ⚠️ Partial |
| ANDROID-WEBVIEW-UNVALIDATED-URL     | CWE-601 | High     | 🔬 In Development |

### B.5 `DeepLinkActivity.kt`

| ID                                 | CWE     | Severity | Status |
|------------------------------------|---------|----------|--------|
| ANDROID-DEEPLINK-NO-VALIDATION     | CWE-939 | High     | ⚠️ Partial |
| ANDROID-FRAGMENT-INJECTION         | CWE-470 | High     | ⚠️ Partial |
| ANDROID-INTENT-UNVALIDATED-FORWARD | CWE-940 | High     | ⚠️ Partial |

### B.6 `FileActivity.kt`

| ID                                | CWE     | Severity | Status |
|-----------------------------------|---------|----------|--------|
| ANDROID-STORAGE-EXTERNAL-SENSITIVE | CWE-312 | High    | ⚠️ Partial |
| ANDROID-STORAGE-WORLD-READABLE    | CWE-732 | High    | ⚠️ Partial |
| ANDROID-PATH-TRAVERSAL            | CWE-22  | High    | ⚠️ Partial |

### B.7 `StorageActivity.kt`

| ID                                  | CWE     | Severity | Status |
|-------------------------------------|---------|----------|--------|
| ANDROID-STORAGE-SQLITE-UNENCRYPTED  | CWE-311 | High    | ⚠️ Partial |
| ANDROID-STORAGE-PLAINTEXT-PASSWORD  | CWE-256 | Critical| ✅ Shipped |
| ANDROID-SQLI-RAW-QUERY              | CWE-89  | Critical| ✅ Shipped |
| ANDROID-INTENT-SENSITIVE-EXTRAS     | CWE-200 | Medium  | ⚠️ Partial |

### B.8 `NetworkActivity.kt`

| ID                                            | CWE     | Severity | Status |
|-----------------------------------------------|---------|----------|--------|
| ANDROID-NETWORK-TRUST-ALL-CERTS               | CWE-295 | Critical| 🔬 In Development |
| ANDROID-NETWORK-PERMISSIVE-HOSTNAME-VERIFIER  | CWE-297 | High    | 🔬 In Development |
| ANDROID-NETWORK-CLEARTEXT-API                 | CWE-319 | High    | ✅ Shipped |
| ANDROID-NETWORK-SECRETS-IN-URL                | CWE-598 | Medium  | ⚠️ Partial |

### B.9 `BroadcastReceiver/InsecureReceiver.kt`

| ID                                            | CWE     | Severity | Status |
|-----------------------------------------------|---------|----------|--------|
| ANDROID-BROADCAST-RECEIVER-NO-PERMISSION-CHECK| CWE-925 | High    | 🔬 In Development |
| ANDROID-BROADCAST-UNVALIDATED-ACTION          | CWE-940 | High    | 🔬 In Development |
| ANDROID-BROADCAST-STICKY-SENSITIVE            | CWE-200 | Medium  | ⚠️ Partial |
