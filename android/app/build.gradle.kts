plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

/**
 * CI 用固定签名：`QP2P_KEYSTORE` 指向从 GitHub Secrets 还原出来的 p12。
 *
 * 不设这个变量（本地开发）就走 AGP 现生成的 debug keystore。
 * 之所以要固定：AGP 的 debug keystore 是每个全新 runner 现生成的随机密钥，
 * 每次构建签名都不同，装到设备上只能「先卸载再装」，配置也一起丢。
 */
val fixedKeystorePath: String? = System.getenv("QP2P_KEYSTORE")?.takeIf { it.isNotEmpty() }

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
        versionCode = 17
        versionName = "0.1.15"
    }

    signingConfigs {
        if (fixedKeystorePath != null) {
            create("fixed") {
                storeFile = file(fixedKeystorePath)
                storeType = "PKCS12"
                keyAlias = System.getenv("QP2P_KEY_ALIAS") ?: "qp2p"
                storePassword = System.getenv("QP2P_KEYSTORE_PASS")
                keyPassword = System.getenv("QP2P_KEYSTORE_PASS")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
        debug {
            // 有固定密钥就用它，出的包才能覆盖升级（不设时保持 AGP 默认行为）
            if (fixedKeystorePath != null) {
                signingConfig = signingConfigs.getByName("fixed")
            }
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
