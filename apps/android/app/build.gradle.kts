plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.serialization")
}

android {
    namespace = "com.pass.android"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.pass.android"
        // D02-MVP: minSdk 26 (Android 8.0) — comfortably covers the
        // EncryptedSharedPreferences (Jetpack Security Crypto) and Android
        // Keystore APIs this app relies on for D4's non-secret account
        // association storage; also matches crates/crypto-ffi/.cargo/config.toml's
        // aarch64-linux-android26-clang NDK toolchain choice.
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0-mvp"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // D02-MVP: the arm64-v8a-only crypto-ffi .so vendored under
        // src/main/jniLibs matches this dev machine's pass_dev emulator
        // (arm64-v8a, Apple Silicon acceleration) and the `pass_dev`/
        // real-device arm64 target this MVP is verified against.
        // Restricting ABI packaging avoids shipping an APK that silently
        // lacks the native lib on other ABIs; adding more ABIs is a
        // follow-up once cross-building for them is set up.
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }

    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }
}

// D02-MVP: unit tests exercise the *real* crypto-ffi (JNA/UniFFI bindings)
// on the host JVM rather than a mocked crypto layer, for the same reason
// the extension's bun tests use the real WASM build — this points JNA at a
// host-architecture (aarch64-apple-darwin, on this dev machine) build of
// crypto-ffi's cdylib, produced by `cargo build --release` from
// crates/crypto-ffi with no --target (native host build), which lands at
// the workspace's shared `target/release/` directory. This is a build-time
// test-runner convenience, not a source-code cross-boundary dependency —
// crates/crypto-ffi remains the only place any Rust is edited.
tasks.withType<Test>().configureEach {
    systemProperty("jna.library.path", File(rootDir, "../../target/release").absolutePath)
    // D02-MVP real-backend integration suite: lets the JVM test locate
    // `apps/android/scripts/integration-fixture.mjs` and run it with `bun`
    // from the repo root (needed for its relative imports of
    // packages/sdk, packages/crypto-worker, and tests/browser/
    // https-fixture.mjs). `rootDir` here is apps/android; the repo root is
    // two levels up.
    systemProperty("pass.repoRootDir", File(rootDir, "../..").absolutePath)
    // Forwarded so the gated integration test can see it exactly as the
    // Bun/extension integration tests do (`System.getenv` alone does not
    // reliably see a value exported in the invoking shell across all
    // Gradle daemon reuse scenarios without this explicit pass-through).
    environment("TEST_DATABASE_URL", System.getenv("TEST_DATABASE_URL") ?: "")
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")

    // D04 analog: non-secret account-association persistence only, via
    // Jetpack Security Crypto's EncryptedSharedPreferences backed by an
    // Android Keystore-generated key (see storage/AccountAssociationStore.kt).
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    // JNI bridge to crypto-ffi's UniFFI-generated Kotlin bindings.
    implementation("net.java.dev.jna:jna:5.15.0@aar")

    // Networking (D1/D3): chosen over Ktor for this MVP because OkHttp is
    // synchronous-callable, has no extra coroutine-engine dependency
    // surface, and is what the JVM ecosystem already reaches for by default
    // for a single-Activity app with no multiplatform target — Ktor's
    // multiplatform engine selection buys nothing here since Android is the
    // only target.
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // Wire (de)serialization for the exact @pass/contracts JSON shapes and
    // ADR-0011 G1's AccountBundle JSON — kotlinx.serialization is pure
    // Kotlin/JVM, so it behaves identically under `testDebugUnitTest` (plain
    // JVM) and on-device, unlike Android's stubbed `org.json` which throws
    // in unit tests without Robolectric.
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
    // The `@aar` JNA artifact above packages only Android-target native
    // libs; JVM unit tests run on the host JVM (not an Android runtime) and
    // need JNA's own host-native dispatch library, which ships inside the
    // plain (non-`@aar`) jar instead.
    testImplementation("net.java.dev.jna:jna:5.15.0")

    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")
    androidTestImplementation(platform("androidx.compose:compose-bom:2024.12.01"))
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
}
