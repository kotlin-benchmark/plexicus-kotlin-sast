// Plexicus SAST benchmark — android-app (Kotlin / AndroidX).
//
// This Gradle script is illustrative of a typical AndroidX Kotlin project. The
// intent is to make the source tree obviously buildable / parseable for SAST
// tooling. The application is intentionally vulnerable.

plugins {
    id("com.android.application") version "8.4.0"
    kotlin("android") version "1.9.22"
}

android {
    namespace = "com.plexicus.android"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.plexicus.android"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            // VULNERABILITY: ProGuard / R8 disabled in release — secrets and rule
            // strings remain in the APK. PLEXICUS-RULE: ANDROID-CONFIG-NO-MINIFY
        }
        getByName("debug") {
            // VULNERABILITY: Debuggable enabled for debug builds — also reflected
            // in AndroidManifest.xml. PLEXICUS-RULE: ANDROID-CONFIG-DEBUGGABLE
            isDebuggable = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("androidx.activity:activity-ktx:1.9.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    implementation("androidx.webkit:webkit:1.11.0")

    // OkHttp is wired up intentionally without certificate pinning.
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    testImplementation("junit:junit:4.13.2")
}
