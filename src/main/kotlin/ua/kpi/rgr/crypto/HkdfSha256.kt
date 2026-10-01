package ua.kpi.rgr.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object HkdfSha256 {
    const val HASH_LENGTH = 32
    const val MAX_OUTPUT_LENGTH = 255 * HASH_LENGTH
    private const val ALGORITHM = "HmacSHA256"

    fun extract(salt: ByteArray, ikm: ByteArray): ByteArray {
        val key = if (salt.isEmpty()) ByteArray(HASH_LENGTH) else salt
        val mac = Mac.getInstance(ALGORITHM)
        mac.init(SecretKeySpec(key, ALGORITHM))
        return mac.doFinal(ikm)
    }

    fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 0..MAX_OUTPUT_LENGTH) { "HKDF output length must be between 0 and $MAX_OUTPUT_LENGTH bytes." }
        require(prk.size >= HASH_LENGTH) { "HKDF PRK must contain at least $HASH_LENGTH bytes." }
        val output = ByteArray(length)
        if (length == 0) return output
        val mac = Mac.getInstance(ALGORITHM)
        mac.init(SecretKeySpec(prk, ALGORITHM))
        var previous = byteArrayOf()
        var offset = 0
        var counter = 1
        while (offset < length) {
            mac.update(previous)
            mac.update(info)
            mac.update(counter.toByte())
            previous = mac.doFinal()
            val count = minOf(HASH_LENGTH, length - offset)
            previous.copyInto(output, offset, 0, count)
            offset += count
            counter++
        }
        return output
    }
}
