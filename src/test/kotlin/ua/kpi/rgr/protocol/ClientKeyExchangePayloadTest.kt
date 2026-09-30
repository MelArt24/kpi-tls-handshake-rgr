package ua.kpi.rgr.protocol

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ClientKeyExchangePayloadTest {
    @Test
    fun `ciphertext survives Base64 and JSON transport round trip`() {
        val encrypted = ByteArray(256) { it.toByte() }
        val message = ClientKeyExchangePayload.encode(encrypted)
        assertEquals(MessageType.CLIENT_KEY_EXCHANGE, message.type)
        assertEquals(setOf("encryptedPremaster"), message.payload.keys)
        val output = ByteArrayOutputStream()
        MessageTransport(ByteArrayInputStream(byteArrayOf()), output).send(message)
        val received = MessageTransport(ByteArrayInputStream(output.toByteArray()), ByteArrayOutputStream()).receive()
        assertContentEquals(encrypted, ClientKeyExchangePayload.decode(received))
    }

    @Test
    fun `missing encrypted premaster is rejected`() {
        assertFailsWith<IOException> { ClientKeyExchangePayload.decode(ProtocolMessage(MessageType.CLIENT_KEY_EXCHANGE)) }
    }

    @Test
    fun `malformed Base64 is rejected`() {
        assertFailsWith<IOException> {
            ClientKeyExchangePayload.decode(ProtocolMessage(MessageType.CLIENT_KEY_EXCHANGE, mapOf("encryptedPremaster" to "%%%")))
        }
    }

    @Test
    fun `wrong message type is rejected`() {
        assertFailsWith<IOException> { ClientKeyExchangePayload.decode(ProtocolMessage(MessageType.CLIENT_HELLO)) }
    }

    @Test
    fun `empty ciphertext is rejected on send and receive`() {
        assertFailsWith<IOException> { ClientKeyExchangePayload.encode(byteArrayOf()) }
        assertFailsWith<IOException> {
            ClientKeyExchangePayload.decode(ProtocolMessage(MessageType.CLIENT_KEY_EXCHANGE, mapOf("encryptedPremaster" to "")))
        }
    }
}
