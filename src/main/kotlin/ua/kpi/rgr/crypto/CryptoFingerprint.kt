package ua.kpi.rgr.crypto

import java.security.MessageDigest
import java.util.HexFormat

object CryptoFingerprint {
    fun sha256Hex(bytes: ByteArray): String =
        HexFormat.of().withUpperCase().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes))
}
