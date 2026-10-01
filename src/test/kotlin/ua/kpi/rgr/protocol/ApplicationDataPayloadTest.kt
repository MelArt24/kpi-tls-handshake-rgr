package ua.kpi.rgr.protocol

import ua.kpi.rgr.crypto.AesGcm
import ua.kpi.rgr.crypto.AesGcmEncrypted
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class ApplicationDataPayloadTest {
    @Test
    fun `JSON transport preserves encrypted data without plaintext`() {
        val text = "Привіт! Як справи?"
        val encrypted = AesGcm.encrypt(text.toByteArray(Charsets.UTF_8), ByteArray(32), "test".toByteArray())
        val message = ApplicationDataPayload.encode(encrypted)
        assertEquals(MessageType.APPLICATION_DATA, message.type)
        assertEquals(setOf("iv", "ciphertext"), message.payload.keys)
        val output = ByteArrayOutputStream()
        MessageTransport(ByteArrayInputStream(byteArrayOf()), output).send(message)
        val wire = output.toString(Charsets.UTF_8)
        assertFalse(wire.contains(text))
        assertEquals(1, wire.count { it == '\n' })
        val received = MessageTransport(ByteArrayInputStream(output.toByteArray()), ByteArrayOutputStream()).receive()
        val decoded = ApplicationDataPayload.decode(received)
        assertContentEquals(encrypted.iv, decoded.iv)
        assertContentEquals(encrypted.ciphertext, decoded.ciphertext)
    }

    @Test
    fun `wrong message type is rejected`() {
        assertFailsWith<IOException> { ApplicationDataPayload.decode(ProtocolMessage(MessageType.CLIENT_FINISHED, validPayload())) }
    }

    @Test
    fun `missing IV and ciphertext are rejected`() {
        for (field in listOf("iv", "ciphertext")) {
            val payload = validPayload().toMutableMap().apply { remove(field) }
            assertFailsWith<IOException> { ApplicationDataPayload.decode(ProtocolMessage(MessageType.APPLICATION_DATA, payload)) }
        }
    }

    @Test
    fun `malformed Base64 in either field is rejected`() {
        for (field in listOf("iv", "ciphertext")) {
            assertFailsWith<IOException> {
                ApplicationDataPayload.decode(ProtocolMessage(MessageType.APPLICATION_DATA, validPayload() + (field to "%%%")))
            }
        }
    }

    @Test
    fun `wrong IV sizes are rejected on encode and decode`() {
        for (size in listOf(0, 11, 13)) {
            assertFailsWith<IOException> { ApplicationDataPayload.encode(AesGcmEncrypted(ByteArray(size), ByteArray(16))) }
            assertFailsWith<IOException> {
                ApplicationDataPayload.decode(ProtocolMessage(MessageType.APPLICATION_DATA, validPayload() + ("iv" to base64(ByteArray(size)))))
            }
        }
    }

    @Test
    fun `empty or incomplete GCM tags are rejected on encode and decode`() {
        for (size in listOf(0, 1, 15)) {
            assertFailsWith<IOException> { ApplicationDataPayload.encode(AesGcmEncrypted(ByteArray(12), ByteArray(size))) }
            assertFailsWith<IOException> {
                ApplicationDataPayload.decode(ProtocolMessage(MessageType.APPLICATION_DATA, validPayload() + ("ciphertext" to base64(ByteArray(size)))))
            }
        }
    }

    private fun validPayload() = mapOf("iv" to base64(ByteArray(12)), "ciphertext" to base64(ByteArray(16)))
    private fun base64(bytes: ByteArray) = Base64.getEncoder().encodeToString(bytes)
}
