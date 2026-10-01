package ua.kpi.rgr.crypto

import java.util.HexFormat
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class HkdfSha256Test {
    @Test
    fun `RFC 5869 appendix A1 verifies PRK and multi block OKM`() {
        // Published known-answer vector: https://www.rfc-editor.org/rfc/rfc5869#appendix-A.1
        val prk = HkdfSha256.extract(hex("000102030405060708090a0b0c"), ByteArray(22) { 0x0b })
        assertContentEquals(hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"), prk)
        val okm = HkdfSha256.expand(prk, hex("f0f1f2f3f4f5f6f7f8f9"), 42)
        assertContentEquals(hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"), okm)
    }

    @Test
    fun `RFC 5869 appendix A3 verifies empty salt and info`() {
        val prk = HkdfSha256.extract(byteArrayOf(), ByteArray(22) { 0x0b })
        assertContentEquals(hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"), prk)
        assertContentEquals(
            hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"),
            HkdfSha256.expand(prk, byteArrayOf(), 42),
        )
    }

    @Test
    fun `zero length expansion returns empty output`() {
        assertContentEquals(byteArrayOf(), HkdfSha256.expand(ByteArray(32), byteArrayOf(), 0))
    }

    @Test
    fun `maximum output is accepted and larger output is rejected`() {
        val prk = ByteArray(32) { it.toByte() }
        assertEquals(8160, HkdfSha256.expand(prk, byteArrayOf(), 8160).size)
        assertFailsWith<IllegalArgumentException> { HkdfSha256.expand(prk, byteArrayOf(), 8161) }
    }

    @Test
    fun `negative length is rejected`() {
        assertFailsWith<IllegalArgumentException> { HkdfSha256.expand(ByteArray(32), byteArrayOf(), -1) }
    }

    @Test
    fun `short PRK is rejected`() {
        assertFailsWith<IllegalArgumentException> { HkdfSha256.expand(ByteArray(31), byteArrayOf(), 32) }
    }

    private fun hex(value: String): ByteArray = HexFormat.of().parseHex(value)
}
