package ua.kpi.rgr.crypto

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.HexFormat

object PremasterSecret {
    const val SIZE = 48
    private val secureRandom = SecureRandom()

    fun generate(): ByteArray = ByteArray(SIZE).also(secureRandom::nextBytes)

    fun fingerprint(bytes: ByteArray): String =
        HexFormat.of().withUpperCase().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes))
}
