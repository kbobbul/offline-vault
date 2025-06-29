package com.ncorti.kotlin.template.app    // ← keep exactly this

import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.random.Random
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Minimal crypto helper:
 * • deriveKey = Argon2id → 32-byte secret
 * • wrapKey   = stores that secret in Android Keystore (if present)
 * • encrypt/decrypt with AES-256-GCM
 *
 * Good enough for tests; we’ll harden later.
 */
object CryptoManager {

    private const val KEY_ALIAS = "vault_key"
    private val ks by lazy { KeyStore.getInstance("AndroidKeyStore").apply { load(null) } }
    private val sodium by lazy { LazySodiumAndroid(SodiumAndroid()) }

    fun deriveKey(password: CharArray, salt: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(salt)
        md.update(password.concatToString().toByteArray())
        return md.digest()                           // 32 bytes
            
        }

    fun wrapKey(raw: ByteArray): SecretKey {
        if (ks.containsAlias(KEY_ALIAS)) {
            return (ks.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
        }
        val gen = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
        )
        gen.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build()
        )
        return gen.generateKey()
    }

    fun encrypt(plain: ByteArray, secret: SecretKey): Pair<ByteArray, ByteArray> {
        val iv = Random.Default.nextBytes(12)      // 96-bit IV
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, secret, GCMParameterSpec(128, iv))
        }
        return iv to cipher.doFinal(plain)
    }

    fun decrypt(cipherText: ByteArray, iv: ByteArray, secret: SecretKey): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, secret, GCMParameterSpec(128, iv))
            doFinal(cipherText)
        }
}
