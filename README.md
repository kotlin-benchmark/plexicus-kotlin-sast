# Plexicus Kotlin SAST Benchmark — Spring Boot + Android

[![Plexicus SAST](https://img.shields.io/badge/Plexicus-SAST-blue)](https://plexicus.com)
[![Language](https://img.shields.io/badge/Kotlin-1.9.22-7F52FF?logo=kotlin)](https://kotlinlang.org)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2.x-6DB33F?logo=springboot)](https://spring.io/projects/spring-boot)
[![Android](https://img.shields.io/badge/Android-AndroidX-3DDC84?logo=android)](https://developer.android.com)
[![DevSkim](https://img.shields.io/badge/DevSkim-Kotlin-success)](https://github.com/microsoft/DevSkim)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-orange)](https://sarifweb.azurewebsites.net)
[![Coverage](https://img.shields.io/badge/Plexicus%20Coverage-P1%20%2F%20Partial-yellow)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-lightgrey.svg)](./LICENSE)

> **F-LANG-03 — Kotlin (Android + Spring Boot)** demonstration repo for the
> Plexicus SAST Engine. This codebase is **intentionally vulnerable** and
> exists solely to benchmark framework-aware Kotlin analysis.

---

## Overview

This repository is the canonical reference implementation for evaluating the
Plexicus SAST Engine against **two distinct Kotlin ecosystems** in one place:

1. **`spring-app/`** — A Kotlin/JVM Spring Boot 3.2 service exhibiting the
   full OWASP Top 10 against a server-side framework (controllers, JPA
   repositories, Thymeleaf, Spring Security).
2. **`android-app/`** — A Kotlin/Android application demonstrating
   mobile-specific weaknesses (intent handling, exported components,
   `WebView` misuse, insecure local storage, cleartext networking, etc.).

The coverage status for Plexicus Kotlin analysis is officially **P1 / Partial**:

- ✅ **Spring Boot (server-side Kotlin)** — broad, production-validated rule
  coverage across SQLi, RCE, deserialization, SSRF, XXE, SSTI, path traversal,
  XSS, authn/authz, and Spring Security misconfiguration.
- ⚠️ **Android (Kotlin)** — partial rule coverage: hardcoded secrets and
  manifest-level checks are production-ready; intent handling, exported
  activity taint, `WebView` `file://` taint, and broadcast receiver runtime
  permission checks are **in development** and not yet fully validated.

See [`docs/coverage-report.md`](./docs/coverage-report.md) for the per-rule
matrix.

---

## Coverage matrix (high level)

| Module        | Language       | Framework    | Rule count | Status                       |
|---------------|----------------|--------------|------------|------------------------------|
| `spring-app/` | Kotlin / JVM   | Spring Boot  | 56         | ✅ Full / Production-validated |
| `android-app/`| Kotlin         | Android (AndroidX) | 21   | ⚠️ Partial / 🔬 In Development |
| **Total**     | **Kotlin**     | **Mixed**    | **77**     | **P1 / Partial**              |

Per-category drill-down lives in [`docs/coverage-report.md`](./docs/coverage-report.md).

---

## Quick start

### Spring Boot service

```bash
cd spring-app
./gradlew bootRun
# Service listens on http://localhost:8080
```

### Android application

```bash
cd android-app
./gradlew :assembleDebug
# APK in android-app/build/outputs/apk/debug/
```

> ⚠️  **Do not** install the Android APK on a personal device. It is
> intentionally vulnerable (cleartext traffic, exported components, world-
> readable storage). Use an emulator/AVD only.

---

## SAST scanning

### Run the full Plexicus pipeline locally

```bash
./scripts/run-plexicus.sh        # Plexicus SAST scan, emits SARIF
./scripts/run-devskim.sh         # Microsoft DevSkim corroboration scan
```

Both scripts produce SARIF 2.1.0 output under `sast/`.

### CI pipelines

| Workflow                                              | What it proves                                         |
|-------------------------------------------------------|--------------------------------------------------------|
| [`.github/workflows/plexicus-sast.yml`](./.github/workflows/plexicus-sast.yml) | Plexicus engine against `spring-app/` + `android-app/` |
| [`.github/workflows/devskim.yml`](./.github/workflows/devskim.yml)             | DevSkim Kotlin pattern detection in CI                 |
| [`.github/workflows/android-sast.yml`](./.github/workflows/android-sast.yml)   | MobSF / Semgrep Android rules pipeline                 |

---

## Findings summary

### `spring-app/` (Kotlin / Spring Boot — ✅ Full coverage)

| File                         | Top findings                                                        |
|------------------------------|---------------------------------------------------------------------|
| `config/SecurityConfig.kt`   | CSRF disabled, CORS `*`, `permitAll()`, `NoOpPasswordEncoder`       |
| `controller/AuthController.kt` | Hardcoded creds, MD5, weak JWT secret, `alg:none`, stacktrace leak |
| `controller/UserController.kt` | SQLi (JdbcTemplate + JPQL), IDOR, mass assignment, XSS              |
| `controller/DataController.kt` | Insecure deserialization, XXE, SSRF, SSTI, zip slip                |
| `controller/FileController.kt` | Path traversal, unrestricted upload                                 |
| `controller/AdminController.kt`| Missing `@PreAuthorize`, command injection                          |
| `service/DataService.kt`       | SQL string interpolation, sensitive logging                         |
| `repository/UserRepository.kt` | `@Query(nativeQuery=true)` concatenation                            |
| `resources/application.yml`    | Hardcoded creds, actuator wildcard, stacktrace exposure             |

### `android-app/` (Kotlin / Android — ⚠️ Partial / 🔬 In Development)

| File                                   | Top findings                                                  |
|----------------------------------------|---------------------------------------------------------------|
| `AndroidManifest.xml`                  | Exported activities, `allowBackup`, `usesCleartextTraffic`    |
| `MainActivity.kt`                      | Unvalidated intent data, sensitive `Log.d`                    |
| `LoginActivity.kt`                     | Plaintext `SharedPreferences`, hardcoded API key, HTTP        |
| `WebViewActivity.kt`                   | JS enabled, `file://` access, `addJavascriptInterface`, SSL bypass |
| `DeepLinkActivity.kt`                  | No host/path validation, fragment injection                   |
| `FileActivity.kt`                      | External storage, `MODE_WORLD_READABLE`, path traversal       |
| `StorageActivity.kt`                   | Unencrypted SQLite, raw SQL concatenation                     |
| `NetworkActivity.kt`                   | Trust-all `X509TrustManager`, permissive `HostnameVerifier`   |
| `BroadcastReceiver/InsecureReceiver.kt`| No permission check, sticky broadcast w/ sensitive data       |

---

## DevSkim Kotlin capability evidence

DevSkim (Microsoft) fires on Kotlin sources in both modules. The SARIF
artifact at [`sast/devskim-results.sarif`](./sast/devskim-results.sarif) is
generated by [`.github/workflows/devskim.yml`](./.github/workflows/devskim.yml)
and demonstrates 12+ unique rule IDs across 25+ results.

Highlight rules:

| DevSkim Rule | Pattern                       | Evidence file                                     |
|--------------|-------------------------------|---------------------------------------------------|
| DS137138     | Weak hash (MD5/SHA1)          | `spring-app/.../service/AuthService.kt`           |
| DS104456     | Hardcoded password / secret   | `android-app/.../LoginActivity.kt`, `application.yml` |
| DS168929     | SQL injection (concatenation) | `controller/UserController.kt`, `StorageActivity.kt` |
| DS440000     | XML external entity (XXE)     | `controller/DataController.kt`                    |
| DS196098     | Insecure random / PRNG        | `service/AuthService.kt`                          |
| DS172411     | Cleartext protocol (HTTP)     | `android-app/.../NetworkActivity.kt`              |

Full evidence table: [`docs/devskim-evidence.md`](./docs/devskim-evidence.md).

---

## Repository layout

```
plexicus-kotlin-sast/
├── README.md                  ← you are here
├── LICENSE
├── .devskim.json              ← DevSkim configuration (Kotlin)
├── .github/workflows/         ← Plexicus + DevSkim + Android pipelines
├── spring-app/                ← Spring Boot 3.2 Kotlin/JVM (✅ Full)
├── android-app/               ← Kotlin Android (⚠️ Partial)
├── docs/                      ← Coverage matrix, findings, remediation
├── sast/                      ← Plexicus rules, SARIF outputs
└── scripts/                   ← Local scan wrappers
```

---

## Documentation

- [`docs/coverage-report.md`](./docs/coverage-report.md) — Full P1/Partial coverage matrix
- [`docs/sast-findings.md`](./docs/sast-findings.md) — Findings catalogue per module
- [`docs/devskim-evidence.md`](./docs/devskim-evidence.md) — DevSkim Kotlin proof
- [`docs/remediation-guide.md`](./docs/remediation-guide.md) — How to fix each class of vulnerability

---

## Disclaimer

This repository contains **intentionally vulnerable** code. Every weakness is
annotated inline:

```kotlin
// VULNERABILITY: <description> — PLEXICUS-RULE: <RULE-ID>
```

Do **not** deploy any artifact from this repository. All "secrets" in config
files are placeholders prefixed with `DEMO_VULN_` and have **no** real
production value.
