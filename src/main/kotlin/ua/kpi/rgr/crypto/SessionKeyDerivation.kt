package ua.kpi.rgr.crypto

import java.io.IOException
import java.security.GeneralSecurityException

data class SessionKeys(
    val clientWriteKey: ByteArray,
    val serverWriteKey: ByteArray,
)

object SessionKeyDerivation {
    const val CONTEXT = "kpi-rgr-tls-session-keys-v1"
    const val KEY_SIZE = 32

    fun derive(premasterSecret: ByteArray, clientRandom: ByteArray, serverRandom: ByteArray): SessionKeys {
        if (premasterSecret.size != PremasterSecret.SIZE) {
            throw IOException("premasterSecret must be exactly ${PremasterSecret.SIZE} bytes.")
        }
        if (clientRandom.size != CryptoRandom.RANDOM_SIZE) {
            throw IOException("clientRandom must be exactly ${CryptoRandom.RANDOM_SIZE} bytes.")
        }
        if (serverRandom.size != CryptoRandom.RANDOM_SIZE) {
            throw IOException("serverRandom must be exactly ${CryptoRandom.RANDOM_SIZE} bytes.")
        }
        try {
            val salt = clientRandom + serverRandom
            val prk = HkdfSha256.extract(salt, premasterSecret)
            val material = HkdfSha256.expand(prk, CONTEXT.toByteArray(Charsets.UTF_8), 2 * KEY_SIZE)
            return SessionKeys(material.copyOfRange(0, KEY_SIZE), material.copyOfRange(KEY_SIZE, 2 * KEY_SIZE))
        } catch (error: GeneralSecurityException) {
            throw IOException("HKDF-SHA256 session key derivation failed.", error)
        }
    }
}
