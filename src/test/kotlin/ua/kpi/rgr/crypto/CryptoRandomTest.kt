package ua.kpi.rgr.crypto

import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class CryptoRandomTest {
    @Test
    fun `generated random contains exactly 32 bytes`() {
        assertEquals(32, CryptoRandom.generateRandomBytes().size)
    }

    @Test
    fun `independently generated random values differ`() {
        val first = CryptoRandom.generateRandomBytes()
        val second = CryptoRandom.generateRandomBytes()
        assertFalse(first.contentEquals(second))
    }

    @Test
    fun `Base64 round trip preserves all random bytes`() {
        val bytes = CryptoRandom.generateRandomBytes()
        val encoded = Base64.getEncoder().encodeToString(bytes)
        assertContentEquals(bytes, Base64.getDecoder().decode(encoded))
    }
}
