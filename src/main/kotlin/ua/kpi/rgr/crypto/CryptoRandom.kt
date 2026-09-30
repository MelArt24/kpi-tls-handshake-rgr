package ua.kpi.rgr.crypto

import java.security.SecureRandom

object CryptoRandom {
    const val RANDOM_SIZE = 32
    private val secureRandom = SecureRandom()

    fun generateRandomBytes(): ByteArray = ByteArray(RANDOM_SIZE).also(secureRandom::nextBytes)
}
