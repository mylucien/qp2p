package com.qp2p

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * 需要加密落盘的少量秘密。
 *
 * 目前只有一个键——[TOKEN]，也就是加入令牌。它等同于入网凭证：拿到就能连上网络，
 * 明文放在 SharedPreferences 里意味着 root 后的设备、`adb backup`、第三方"清理"
 * 工具都能直接读走。所以这里用 Android Keystore 里的 AES-256-GCM 加密后再存。
 *
 * 几个刻意的决定：
 *
 * - **密钥不可导出**，留在 Keystore 里，只把 IV + 密文写进 prefs。因此密文
 *   离开这台设备就没有意义；反过来重装应用/换机/从备份恢复之后旧密文解不开，
 *   这是预期行为——令牌本来就要重新导一次（见 [get] 的失败处理）。
 * - **加密失败绝不退回明文**。Keystore 不可用时 [put] 返回 false，让界面报错；
 *   悄悄写明文等于把这次要修的问题换个地方留下来。
 * - **读取时顺手升级老数据**：旧版本存的明文没有 `v1:` 前缀，读到就地加密回写，
 *   用户不用手动重填。
 */
object Secrets {
    private const val TAG = "qp2p/Secrets"
    private const val KEYSTORE = "AndroidKeyStore"
    private const val ALIAS = "qp2p.secret.v1"
    private const val TRANSFORM = "AES/GCM/NoPadding"
    private const val PREFIX = "v1:"
    private const val IV_LEN = 12
    private const val TAG_BITS = 128

    /** 加入令牌的 prefs 键（与界面共用同一个名字） */
    const val TOKEN = "token"

    @Volatile
    private var cached: SecretKey? = null

    /**
     * 读一个秘密。
     *
     * 没有值、或密文解不开时返回空串——两种情况对调用方的意义一样：需要用户重新填。
     * 解不开时**不删**原值，万一用户要回退到旧版本还能用。
     */
    fun get(context: Context, key: String): String {
        val prefs = context.getSharedPreferences(AppConfig.PREFS, Context.MODE_PRIVATE)
        val raw = prefs.getString(key, null).orEmpty()
        if (raw.isEmpty()) return ""
        if (!raw.startsWith(PREFIX)) {
            // 旧版本留下的明文：读到就升级，别等用户再点一次"保存"
            put(context, key, raw)
            return raw
        }
        return try {
            decrypt(raw.substring(PREFIX.length))
        } catch (e: Exception) {
            Log.w(TAG, "解密 $key 失败（密钥可能已随重装丢失）：${e.javaClass.simpleName} ${e.message}")
            ""
        }
    }

    /**
     * 写一个秘密。
     *
     * @return false 表示没能安全保存（Keystore 不可用），调用方必须提示用户
     */
    fun put(context: Context, key: String, value: String): Boolean {
        val prefs = context.getSharedPreferences(AppConfig.PREFS, Context.MODE_PRIVATE)
        if (value.isEmpty()) {
            prefs.edit().remove(key).apply()
            return true
        }
        val enc = try {
            encrypt(value)
        } catch (e: Exception) {
            Log.e(TAG, "加密 $key 失败：${e.javaClass.simpleName} ${e.message}")
            return false
        }
        prefs.edit().putString(key, PREFIX + enc).apply()
        return true
    }

    private fun key(): SecretKey {
        cached?.let { return it }
        val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (store.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey?.let {
            cached = it
            return it
        }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        gen.init(
            KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return gen.generateKey().also { cached = it }
    }

    private fun encrypt(plain: String): String {
        val cipher = Cipher.getInstance(TRANSFORM)
        // 不自己造 IV：Keystore 默认要求随机 IV，由它生成并读回来
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val iv = cipher.iv
        val body = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
        val all = ByteArray(iv.size + body.size)
        iv.copyInto(all)
        body.copyInto(all, iv.size)
        return Base64.encodeToString(all, Base64.NO_WRAP)
    }

    private fun decrypt(text: String): String {
        val all = Base64.decode(text, Base64.NO_WRAP)
        require(all.size > IV_LEN) { "密文长度不对" }
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG_BITS, all, 0, IV_LEN))
        return String(cipher.doFinal(all, IV_LEN, all.size - IV_LEN), Charsets.UTF_8)
    }
}
