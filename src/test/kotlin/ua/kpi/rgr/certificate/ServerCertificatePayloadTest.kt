package ua.kpi.rgr.certificate

import ua.kpi.rgr.protocol.MessageType
import ua.kpi.rgr.protocol.ProtocolMessage
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.Base64
import ua.kpi.rgr.protocol.MessageTransport
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ServerCertificatePayloadTest {
    @Test
    fun `certificate Base64 DER round trip preserves certificate`() {
        val encoded = ServerCertificatePayload.encode(certificate)
        assertContentEquals(certificate.encoded, Base64.getDecoder().decode(encoded))
        assertEquals(certificate, ServerCertificatePayload.decode(message(encoded)))
    }

    @Test
    fun `certificate and random travel together on one JSON line`() {
        val hello = ProtocolMessage(MessageType.SERVER_HELLO, mapOf(
            "serverRandom" to Base64.getEncoder().encodeToString(ByteArray(32)),
            ServerCertificatePayload.FIELD to ServerCertificatePayload.encode(certificate),
        ))
        val output = ByteArrayOutputStream()
        MessageTransport(ByteArrayInputStream(byteArrayOf()), output).send(hello)
        assertEquals(1, output.toString(Charsets.UTF_8).count { it == '\n' })
        val received = MessageTransport(ByteArrayInputStream(output.toByteArray()), ByteArrayOutputStream()).receive()
        assertEquals(hello, received)
        assertEquals(certificate, ServerCertificatePayload.decode(received))
    }

    @Test
    fun `missing certificate field is rejected`() {
        val error = assertFailsWith<IOException> {
            ServerCertificatePayload.decode(ProtocolMessage(MessageType.SERVER_HELLO))
        }
        assertTrue(error.message.orEmpty().contains("missing the 'serverCertificate'"))
    }

    @Test
    fun `malformed Base64 is rejected`() {
        val error = assertFailsWith<IOException> { ServerCertificatePayload.decode(message("%%%")) }
        assertTrue(error.message.orEmpty().contains("Invalid Base64"))
    }

    @Test
    fun `non certificate bytes are rejected`() {
        val error = assertFailsWith<IOException> {
            ServerCertificatePayload.decode(message(Base64.getEncoder().encodeToString(ByteArray(32) { it.toByte() })))
        }
        assertTrue(error.message.orEmpty().contains("Invalid X.509"))
    }

    @Test
    fun `DER with trailing bytes is rejected`() {
        assertFailsWith<IOException> {
            ServerCertificatePayload.decode(message(Base64.getEncoder().encodeToString(certificate.encoded + byteArrayOf(1))))
        }
    }

    private fun message(encoded: String) = ProtocolMessage(
        MessageType.SERVER_HELLO, mapOf(ServerCertificatePayload.FIELD to encoded),
    )

    companion object {
        private val certificate by lazy { CertificateGenerator().generate().serverCertificate }
    }
}
