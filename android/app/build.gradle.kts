plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.qp2p"
    compileSdk = 34
    // NDK 由 CI 的 cargo-ndk 用，这里只需要版本对上
    ndkVersion = "26.1.10909125"

    defaultConfig {
        applicationId = "com.qp2p"
        // 下限是 Android 6.0（API 23）：界面用了 Material 主题和
        // SYSTEM_UI_FLAG_LIGHT_STATUS_BAR，二者都要 23；NotificationChannel
        // （26）那段本来就有 SDK_INT 判断。再往下要换主题、改状态栏写法，
        // 而 NDK r26 与 Rust 的 android target 也只保证到 API 21，不值当。
        // 电视盒子大量停在 6.0，所以水位跟着盒子走，不跟着手机走。
        minSdk = 23
        targetSdk = 34
        versionCode = 10
        versionName = "0.1.8"
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
}
