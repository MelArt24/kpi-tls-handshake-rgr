package ua.kpi.rgr.crypto

import java.io.IOException
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class AesGcmEncrypted(
    val iv: ByteArray,
    val ciphertext: ByteArray,
)

object AesGcm {
    const val KEY_SIZE = 32
    const val IV_SIZE = 12
    const val TAG_BITS = 128
    private val random = SecureRandom()

    fun encrypt(plaintext: ByteArray, key: ByteArray, aad: ByteArray): AesGcmEncrypted {
        requireKey(key)
        val iv = ByteArray(IV_SIZE).also(random::nextBytes)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
            cipher.updateAAD(aad)
            return AesGcmEncrypted(iv, cipher.doFinal(plaintext))
        } catch (error: GeneralSecurityException) {
            throw IOException("AES-GCM encryption failed.", error)
        }
    }

    fun decrypt(encrypted: AesGcmEncrypted, key: ByteArray, aad: ByteArray): ByteArray {
        requireKey(key)
        if (encrypted.iv.size != IV_SIZE) throw IOException("AES-GCM IV must be exactly $IV_SIZE bytes.")
        if (encrypted.ciphertext.size < TAG_BITS / 8) throw IOException("AES-GCM ciphertext must include a 128-bit authentication tag.")
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, encrypted.iv))
            cipher.updateAAD(aad)
            return cipher.doFinal(encrypted.ciphertext)
        } catch (error: AEADBadTagException) {
            throw IOException("AES-GCM authentication failed.", error)
        } catch (error: GeneralSecurityException) {
            throw IOException("AES-GCM decryption failed.", error)
        }
    }

    private fun requireKey(key: ByteArray) {
        if (key.size != KEY_SIZE) throw IOException("AES-256-GCM key must be exactly $KEY_SIZE bytes.")
    }
}
