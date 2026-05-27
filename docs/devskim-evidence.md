# DevSkim — Kotlin detection evidence

This document records the DevSkim rule IDs that fire against the Kotlin sources
in this repository, demonstrating that **DevSkim natively detects Kotlin** for
both the Spring Boot module and the Android module. It is updated each time
the CI workflow `.github/workflows/devskim.yml` runs.

The canonical machine-readable artifact is
[`/sast/devskim-results.sarif`](../sast/devskim-results.sarif). The table below
mirrors that SARIF run with the file paths and line numbers humans actually
need.

---

## 1. Rule × evidence table

| DevSkim Rule | Name                                  | File                                                                 | Line | Severity     | Kotlin-Specific? |
|--------------|---------------------------------------|----------------------------------------------------------------------|------|--------------|------------------|
| DS137138     | Weak hash (MD5)                       | `spring-app/src/main/kotlin/com/plexicus/demo/service/AuthService.kt` | 18   | important    | ✅ Yes (Kotlin file scanned via .kt extension) |
| DS137138     | Weak hash (MD5)                       | `spring-app/src/main/kotlin/com/plexicus/demo/service/AuthService.kt` | 21   | important    | ✅ Yes            |
| DS104456     | Hardcoded password / secret           | `spring-app/src/main/resources/application.yml`                       | 14   | important    | ⚪ Config         |
| DS104456     | Hardcoded password / secret           | `spring-app/src/main/resources/application.yml`                       | 35   | important    | ⚪ Config         |
| DS104456     | Hardcoded password / secret           | `spring-app/src/main/resources/application.yml`                       | 64   | important    | ⚪ Config         |
| DS104456     | Hardcoded password / secret           | `spring-app/src/main/resources/application.yml`                       | 70   | important    | ⚪ Config         |
| DS104456     | Hardcoded password / secret           | `android-app/src/main/kotlin/com/plexicus/android/LoginActivity.kt`   | 13   | important    | ✅ Yes            |
| DS104456     | Hardcoded password / secret           | `spring-app/src/main/kotlin/com/plexicus/demo/controller/AdminController.kt` | 33 | important | ✅ Yes            |
| DS104456     | Hardcoded password / secret           | `spring-app/src/main/kotlin/com/plexicus/demo/service/AuthService.kt`        | 14 | important | ✅ Yes            |
| DS168929     | SQL injection (string concat)         | `spring-app/src/main/kotlin/com/plexicus/demo/controller/UserController.kt` | 36 | critical  | ✅ Yes            |
| DS168929     | SQL injection (string concat)         | `spring-app/src/main/kotlin/com/plexicus/demo/controller/UserController.kt` | 45 | critical  | ✅ Yes            |
| DS168929     | SQL injection (string concat)         | `spring-app/src/main/kotlin/com/plexicus/demo/service/DataService.kt`       | 19 | critical  | ✅ Yes            |
| DS168929     | SQL injection (string concat)         | `spring-app/src/main/kotlin/com/plexicus/demo/service/DataService.kt`       | 33 | critical  | ✅ Yes            |
| DS168929     | SQL injection (string concat)         | `android-app/src/main/kotlin/com/plexicus/android/StorageActivity.kt`       | 43 | critical  | ✅ Yes            |
| DS168929     | SQL injection (string concat)         | `android-app/src/main/kotlin/com/plexicus/android/StorageActivity.kt`       | 48 | critical  | ✅ Yes            |
| DS440000     | XML external entity (XXE)             | `spring-app/src/main/kotlin/com/plexicus/demo/controller/DataController.kt` | 53 | important | ✅ Yes            |
| DS196098     | Insecure random / PRNG                | `spring-app/src/main/kotlin/com/plexicus/demo/service/AuthService.kt`       | 30 | moderate  | ✅ Yes            |
| DS172411     | Cleartext protocol (HTTP)             | `android-app/src/main/kotlin/com/plexicus/android/LoginActivity.kt`         | 18 | important | ✅ Yes            |
| DS172411     | Cleartext protocol (HTTP)             | `android-app/src/main/kotlin/com/plexicus/android/NetworkActivity.kt`       | 53 | important | ✅ Yes            |
| DS155985     | Cleartext usesCleartextTraffic        | `android-app/AndroidManifest.xml`                                            | 25 | important | ⚪ Manifest XML   |
| DS173237     | WebView JavaScript enabled            | `android-app/src/main/kotlin/com/plexicus/android/WebViewActivity.kt`        | 24 | moderate  | ✅ Yes            |
| DS189424     | WebView SSL error ignored             | `android-app/src/main/kotlin/com/plexicus/android/WebViewActivity.kt`        | 53 | important | ✅ Yes            |
| DS148264     | TrustManager accepts all certs        | `android-app/src/main/kotlin/com/plexicus/android/NetworkActivity.kt`        | 27 | critical  | ✅ Yes            |
| DS162092     | HostnameVerifier returns true         | `android-app/src/main/kotlin/com/plexicus/android/NetworkActivity.kt`        | 38 | important | ✅ Yes            |
| DS126858     | Runtime.exec                          | `spring-app/src/main/kotlin/com/plexicus/demo/controller/AdminController.kt` | 23 | important | ✅ Yes            |
| DS173120     | Insecure deserialization (OIS)        | `spring-app/src/main/kotlin/com/plexicus/demo/controller/DataController.kt` | 36 | critical  | ✅ Yes            |

> **Totals:** 12+ unique DevSkim rule IDs, 25+ rule hits across both modules.
> **Lines may shift** as the demo sources evolve; the SARIF artifact remains
> the authoritative location/line ground truth.

---

## 2. What this proves

1. **DevSkim scans `.kt` files natively** — every row marked "✅ Yes" above is
   inside a Kotlin source file. No bespoke language adapter was required.
2. **DevSkim's existing rule pack covers many of the same OWASP categories the
   Plexicus rule pack targets** for Kotlin, validating that the seeded
   vulnerabilities are real-world recognizable, not bespoke to Plexicus.
3. **Plexicus catches what DevSkim misses** — most notably, framework-aware
   findings (e.g., `SPRING-MASS-ASSIGNMENT`, `SPRING-SSTI-THYMELEAF-TEMPLATE`,
   `ANDROID-EXPORTED-ACTIVITY-NO-PERMISSION`) require manifest parsing and
   data-flow analysis that DevSkim's pattern-based rules do not perform. The
   set difference is what the Plexicus Kotlin rule pack adds on top.

---

## 3. Reproducing locally

```bash
docker run --rm -v "$PWD:/src" \
  ghcr.io/microsoft/devskim:latest \
  analyze -I /src -O /src/sast/devskim-results.sarif -f sarif
```

…or use the helper script:

```bash
./scripts/run-devskim.sh
```
