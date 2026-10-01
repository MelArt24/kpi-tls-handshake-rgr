package ua.kpi.rgr.protocol

import ua.kpi.rgr.crypto.AesGcm
import ua.kpi.rgr.crypto.AesGcmEncrypted
import ua.kpi.rgr.crypto.SessionKeyDerivation
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class FinishedPayloadTest {
    private val types = listOf(MessageType.CLIENT_FINISHED, MessageType.SERVER_FINISHED)
    private val key = ByteArray(32) { it.toByte() }

    @Test
    fun `both Finished types round trip through JSON without plaintext or keys`() {
        for (type in types) {
            val ready = if (type == MessageType.CLIENT_FINISHED) "CLIENT_READY" else "SERVER_READY"
            val encrypted = AesGcm.encrypt(ready.toByteArray(Charsets.UTF_8), key, aad(type))
            val message = FinishedPayload.encode(type, encrypted)
            assertEquals(setOf("iv", "ciphertext"), message.payload.keys)
            val output = ByteArrayOutputStream()
            MessageTransport(ByteArrayInputStream(byteArrayOf()), output).send(message)
            val wire = output.toString(Charsets.UTF_8)
            assertEquals(1, wire.count { it == '\n' })
            assertFalse(wire.contains(ready))
            assertFalse(wire.contains(Base64.getEncoder().encodeToString(key)))
            val received = MessageTransport(ByteArrayInputStream(output.toByteArray()), ByteArrayOutputStream()).receive()
            val decoded = FinishedPayload.decode(received, type)
            assertContentEquals(encrypted.iv, decoded.iv)
            assertContentEquals(encrypted.ciphertext, decoded.ciphertext)
            assertEquals(ready, FinishedPayload.decryptReady(received, type, key))
        }
    }

    @Test
    fun `unexpected type is rejected on encode and decode`() {
        val encrypted = AesGcmEncrypted(ByteArray(12), ByteArray(16))
        assertFailsWith<IOException> { FinishedPayload.encode(MessageType.CLIENT_HELLO, encrypted) }
        assertFailsWith<IOException> { FinishedPayload.decode(ProtocolMessage(MessageType.CLIENT_HELLO), MessageType.CLIENT_FINISHED) }
        assertFailsWith<IOException> { FinishedPayload.decode(ProtocolMessage(MessageType.SERVER_FINISHED), MessageType.CLIENT_FINISHED) }
    }

    @Test
    fun `missing IV or ciphertext is rejected`() {
        for (field in listOf("iv", "ciphertext")) {
            val payload = validPayload().toMutableMap().apply { remove(field) }
            assertFailsWith<IOException> { FinishedPayload.decode(ProtocolMessage(MessageType.CLIENT_FINISHED, payload), MessageType.CLIENT_FINISHED) }
        }
    }

    @Test
    fun `malformed Base64 in either field is rejected`() {
        for (field in listOf("iv", "ciphertext")) {
            val payload = validPayload() + (field to "%%%")
            assertFailsWith<IOException> { FinishedPayload.decode(ProtocolMessage(MessageType.CLIENT_FINISHED, payload), MessageType.CLIENT_FINISHED) }
        }
    }

    @Test
    fun `invalid IV and empty ciphertext are rejected`() {
        for (size in listOf(0, 11, 13)) {
            val encrypted = AesGcmEncrypted(ByteArray(size), ByteArray(16))
            assertFailsWith<IOException> { FinishedPayload.encode(MessageType.CLIENT_FINISHED, encrypted) }
            val payload = validPayload() + ("iv" to Base64.getEncoder().encodeToString(encrypted.iv))
            assertFailsWith<IOException> { FinishedPayload.decode(ProtocolMessage(MessageType.CLIENT_FINISHED, payload), MessageType.CLIENT_FINISHED) }
        }
        assertFailsWith<IOException> { FinishedPayload.encode(MessageType.CLIENT_FINISHED, AesGcmEncrypted(ByteArray(12), byteArrayOf())) }
        assertFailsWith<IOException> {
            FinishedPayload.decode(ProtocolMessage(MessageType.CLIENT_FINISHED, validPayload() + ("ciphertext" to "")), MessageType.CLIENT_FINISHED)
        }
    }

    @Test
    fun `matching directional keys recover exact READY bytes`() {
        val premaster = ByteArray(48) { it.toByte() }
        val clientRandom = ByteArray(32) { (it + 48).toByte() }
        val serverRandom = ByteArray(32) { (it + 80).toByte() }
        val clientKeys = SessionKeyDerivation.derive(premaster, clientRandom, serverRandom)
        val serverKeys = SessionKeyDerivation.derive(premaster.copyOf(), clientRandom.copyOf(), serverRandom.copyOf())
        val clientReady = "CLIENT_READY".toByteArray(Charsets.UTF_8)
        val serverReady = "SERVER_READY".toByteArray(Charsets.UTF_8)
        val clientEncrypted = AesGcm.encrypt(clientReady, clientKeys.clientWriteKey, aad(MessageType.CLIENT_FINISHED))
        assertContentEquals(clientReady, AesGcm.decrypt(clientEncrypted, serverKeys.clientWriteKey, aad(MessageType.CLIENT_FINISHED)))
        assertFailsWith<IOException> { AesGcm.decrypt(clientEncrypted, serverKeys.serverWriteKey, aad(MessageType.CLIENT_FINISHED)) }
        val serverEncrypted = AesGcm.encrypt(serverReady, serverKeys.serverWriteKey, aad(MessageType.SERVER_FINISHED))
        assertContentEquals(serverReady, AesGcm.decrypt(serverEncrypted, clientKeys.serverWriteKey, aad(MessageType.SERVER_FINISHED)))
    }

    @Test
    fun `changing visible Finished type fails GCM authentication`() {
        val encrypted = AesGcm.encrypt("CLIENT_READY".toByteArray(Charsets.UTF_8), key, aad(MessageType.CLIENT_FINISHED))
        val message = FinishedPayload.encode(MessageType.CLIENT_FINISHED, encrypted).copy(type = MessageType.SERVER_FINISHED)
        assertFailsWith<IOException> { FinishedPayload.decryptReady(message, MessageType.SERVER_FINISHED, key) }
    }

    @Test
    fun `authenticated but incorrect READY plaintext is rejected`() {
        for (type in types) {
            for (wrong in listOf("WRONG_READY", "CLIENT_READY\n", "SERVER_READY ")) {
                val encrypted = AesGcm.encrypt(wrong.toByteArray(Charsets.UTF_8), key, aad(type))
                val message = FinishedPayload.encode(type, encrypted)
                assertFailsWith<IOException> { FinishedPayload.decryptReady(message, type, key) }
            }
        }
    }

    private fun aad(type: MessageType) = type.name.toByteArray(Charsets.UTF_8)

    private fun validPayload() = mapOf(
        "iv" to Base64.getEncoder().encodeToString(ByteArray(12)),
        "ciphertext" to Base64.getEncoder().encodeToString(ByteArray(16)),
    )
}
