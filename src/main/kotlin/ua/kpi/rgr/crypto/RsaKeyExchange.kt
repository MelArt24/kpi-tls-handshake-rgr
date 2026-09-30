package ua.kpi.rgr.crypto

import java.io.IOException
import java.security.GeneralSecurityException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

object RsaKeyExchange {
    private val oaepParameters = OAEPParameterSpec(
        "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT,
    )

    fun encryptPremaster(premaster: ByteArray, publicKey: PublicKey): ByteArray {
        if (publicKey !is RSAPublicKey) throw IOException("Premaster encryption requires an RSA public key.")
        if (premaster.size != PremasterSecret.SIZE) throw IOException("Premaster secret must be exactly 48 bytes.")
        try {
            val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParameters)
            return cipher.doFinal(premaster)
        } catch (error: GeneralSecurityException) {
            throw IOException("RSA-OAEP premaster encryption failed.", error)
        }
    }

    fun decryptPremaster(encrypted: ByteArray, privateKey: PrivateKey): ByteArray {
        if (privateKey !is RSAPrivateKey) throw IOException("Premaster decryption requires an RSA private key.")
        val ciphertextSize = (privateKey.modulus.bitLength() + 7) / 8
        if (encrypted.size != ciphertextSize) throw IOException("Invalid RSA premaster ciphertext length.")
        val premaster = try {
            val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
            cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParameters)
            cipher.doFinal(encrypted)
        } catch (error: GeneralSecurityException) {
            throw IOException("RSA-OAEP premaster decryption failed.", error)
        }
        if (premaster.size != PremasterSecret.SIZE) throw IOException("Recovered premaster secret must be exactly 48 bytes.")
        return premaster
    }
}
