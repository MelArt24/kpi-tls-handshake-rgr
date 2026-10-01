package ua.kpi.rgr.crypto

import java.security.SecureRandom

object PremasterSecret {
    const val SIZE = 48
    private val secureRandom = SecureRandom()

    fun generate(): ByteArray = ByteArray(SIZE).also(secureRandom::nextBytes)

}
