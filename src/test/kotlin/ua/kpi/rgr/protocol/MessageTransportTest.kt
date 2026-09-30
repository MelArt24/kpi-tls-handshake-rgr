package ua.kpi.rgr.protocol

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class MessageTransportTest {
    @Test
    fun `JSON round trip preserves type and named textual fields`() {
        val message = ProtocolMessage(
            MessageType.CLIENT_HELLO,
            mapOf("message" to "Hello from client with spaces", "note" to "Ordinary text: 123"),
        )
        assertEquals(message, Json.decodeFromString<ProtocolMessage>(Json.encodeToString(message)))
    }

    @Test
    fun `transport round trip preserves UTF-8 and escapes embedded newlines`() {
        val message = ProtocolMessage(
            MessageType.SERVER_HELLO,
            mapOf("message" to "Hello with spaces\nSecond line\r\nПривіт \"client\" \\"),
        )
        val output = ByteArrayOutputStream()
        MessageTransport(ByteArrayInputStream(byteArrayOf()), output).send(message)

        val wire = output.toString(Charsets.UTF_8)
        assertTrue(wire.endsWith("\n"))
        assertEquals(1, wire.count { it == '\n' })
        val receiver = MessageTransport(ByteArrayInputStream(output.toByteArray()), ByteArrayOutputStream())
        assertEquals(message, receiver.receive())
    }

    @Test
    fun `successive messages remain separate lines`() {
        val output = ByteArrayOutputStream()
        val sender = MessageTransport(ByteArrayInputStream(byteArrayOf()), output)
        val request = ProtocolMessage(MessageType.CLIENT_HELLO)
        val response = ProtocolMessage(MessageType.SERVER_HELLO)
        sender.send(request)
        sender.send(response)
        val receiver = MessageTransport(ByteArrayInputStream(output.toByteArray()), ByteArrayOutputStream())
        assertEquals(request, receiver.receive())
        assertEquals(response, receiver.receive())
        assertFailsWith<EOFException> { receiver.receive() }
    }

    @Test
    fun `malformed JSON is rejected clearly`() {
        val transport = transportFor("not JSON\n")
        val error = assertFailsWith<IOException> { transport.receive() }
        assertTrue(error.message.orEmpty().startsWith("Malformed protocol message:"))
    }

    @Test
    fun `unknown message type is rejected`() {
        val transport = transportFor("""{"type":"UNKNOWN","payload":{}}""" + "\n")
        assertFailsWith<IOException> { transport.receive() }
    }

    @Test
    fun `end of stream is reported clearly`() {
        val error = assertFailsWith<EOFException> { transportFor("").receive() }
        assertTrue(error.message.orEmpty().contains("Connection closed"))
    }

    private fun transportFor(wire: String) = MessageTransport(
        ByteArrayInputStream(wire.toByteArray(Charsets.UTF_8)),
        ByteArrayOutputStream(),
    )
}
