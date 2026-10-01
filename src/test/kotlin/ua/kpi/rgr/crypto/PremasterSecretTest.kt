package ua.kpi.rgr.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class PremasterSecretTest {
    @Test
    fun `premaster contains exactly 48 bytes`() {
        assertEquals(48, PremasterSecret.generate().size)
    }

    @Test
    fun `independent premaster values differ`() {
        assertFalse(PremasterSecret.generate().contentEquals(PremasterSecret.generate()))
    }

    @Test
    fun `fingerprint is uppercase SHA256 hex`() {
        assertEquals(
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
            CryptoFingerprint.sha256Hex("abc".toByteArray(Charsets.UTF_8)),
        )
    }
}
