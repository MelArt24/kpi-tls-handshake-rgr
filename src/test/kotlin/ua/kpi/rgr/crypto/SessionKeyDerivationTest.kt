package ua.kpi.rgr.crypto

import java.io.IOException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SessionKeyDerivationTest {
    private val premaster = ByteArray(48) { it.toByte() }
    private val clientRandom = ByteArray(32) { (it + 48).toByte() }
    private val serverRandom = ByteArray(32) { (it + 80).toByte() }

    @Test
    fun `directional keys each contain 32 bytes and differ`() {
        val keys = derive()
        assertEquals(32, keys.clientWriteKey.size)
        assertEquals(32, keys.serverWriteKey.size)
        assertFalse(keys.clientWriteKey.contentEquals(keys.serverWriteKey))
    }

    @Test
    fun `independent client and server derivations match direction by direction`() {
        val clientKeys = derive()
        val serverKeys = SessionKeyDerivation.derive(premaster.copyOf(), clientRandom.copyOf(), serverRandom.copyOf())
        assertContentEquals(clientKeys.clientWriteKey, serverKeys.clientWriteKey)
        assertContentEquals(clientKeys.serverWriteKey, serverKeys.serverWriteKey)
    }

    @Test
    fun `changing premaster changes both keys`() {
        assertDifferent(derive(), SessionKeyDerivation.derive(changed(premaster), clientRandom, serverRandom))
    }

    @Test
    fun `changing client random changes both keys`() {
        assertDifferent(derive(), SessionKeyDerivation.derive(premaster, changed(clientRandom), serverRandom))
    }

    @Test
    fun `changing server random changes both keys`() {
        assertDifferent(derive(), SessionKeyDerivation.derive(premaster, clientRandom, changed(serverRandom)))
    }

    @Test
    fun `reversing random order changes both keys`() {
        assertDifferent(derive(), SessionKeyDerivation.derive(premaster, serverRandom, clientRandom))
    }

    @Test
    fun `derivation uses specified salt context and output split`() {
        val prk = HkdfSha256.extract(clientRandom + serverRandom, premaster)
        val output = HkdfSha256.expand(prk, "kpi-rgr-tls-session-keys-v1".toByteArray(Charsets.UTF_8), 64)
        val keys = derive()
        assertContentEquals(output.copyOfRange(0, 32), keys.clientWriteKey)
        assertContentEquals(output.copyOfRange(32, 64), keys.serverWriteKey)
    }

    @Test
    fun `invalid premaster lengths identify the input`() {
        for (size in listOf(0, 47, 49)) {
            val error = assertFailsWith<IOException> { SessionKeyDerivation.derive(ByteArray(size), clientRandom, serverRandom) }
            assertTrue(error.message.orEmpty().contains("premasterSecret"))
        }
    }

    @Test
    fun `invalid client random lengths identify the input`() {
        for (size in listOf(0, 31, 33)) {
            val error = assertFailsWith<IOException> { SessionKeyDerivation.derive(premaster, ByteArray(size), serverRandom) }
            assertTrue(error.message.orEmpty().contains("clientRandom"))
        }
    }

    @Test
    fun `invalid server random lengths identify the input`() {
        for (size in listOf(0, 31, 33)) {
            val error = assertFailsWith<IOException> { SessionKeyDerivation.derive(premaster, clientRandom, ByteArray(size)) }
            assertTrue(error.message.orEmpty().contains("serverRandom"))
        }
    }

    private fun derive() = SessionKeyDerivation.derive(premaster, clientRandom, serverRandom)

    private fun changed(bytes: ByteArray) = bytes.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }

    private fun assertDifferent(first: SessionKeys, second: SessionKeys) {
        assertFalse(first.clientWriteKey.contentEquals(second.clientWriteKey))
        assertFalse(first.serverWriteKey.contentEquals(second.serverWriteKey))
    }
}
