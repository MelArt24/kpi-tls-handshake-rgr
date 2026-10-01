package ua.kpi.rgr.protocol

import ua.kpi.rgr.certificate.CertificateGenerator
import ua.kpi.rgr.certificate.ServerCertificatePayload
import ua.kpi.rgr.crypto.PremasterSecret
import ua.kpi.rgr.crypto.RsaKeyExchange
import ua.kpi.rgr.crypto.SecureApplicationData
import ua.kpi.rgr.crypto.SessionKeyDerivation
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class FragmentedMessageTransportTest {
    @Test
    fun `CLIENT_HELLO is transparent to callers`() {
        val hello = ProtocolMessage(MessageType.CLIENT_HELLO, mapOf("clientRandom" to Base64.getEncoder().encodeToString(ByteArray(32))))
        assertEquals(hello, roundTrip(hello))
    }

    @Test
    fun `real certificate SERVER_HELLO spans packets and recovers exact X509`() {
        val hello = ProtocolMessage(MessageType.SERVER_HELLO, mapOf(
            "serverRandom" to Base64.getEncoder().encodeToString(ByteArray(32)),
            "serverCertificate" to ServerCertificatePayload.encode(material.serverCertificate),
        ))
        val recovered = roundTrip(hello, multiple = true)
        assertEquals(hello, recovered)
        assertEquals(material.serverCertificate, ServerCertificatePayload.decode(recovered))
    }

    @Test
    fun `RSA2048 CLIENT_KEY_EXCHANGE fragments without changing ciphertext`() {
        val premaster = PremasterSecret.generate()
        val encrypted = RsaKeyExchange.encryptPremaster(premaster, material.serverCertificate.publicKey)
        val message = ClientKeyExchangePayload.encode(encrypted)
        val recovered = roundTrip(message, multiple = true)
        assertEquals(message, recovered)
        assertContentEquals(premaster, RsaKeyExchange.decryptPremaster(ClientKeyExchangePayload.decode(recovered), material.serverKeyPair.private))
    }

    @Test
    fun `long Ukrainian encrypted chat fragments before authenticated decryption`() {
        val keys = SessionKeyDerivation.derive(ByteArray(48), ByteArray(32), ByteArray(32) { 1 })
        val text = "Привіт! Як справи? 👋\n".repeat(200)
        val message = SecureApplicationData.encryptClientToServer(text, keys)
        val recovered = roundTrip(message, multiple = true)
        assertEquals(message, recovered)
        assertEquals(text, SecureApplicationData.decryptClientToServer(recovered, keys))
    }

    @Test
    fun `invalid reconstructed UTF8 is rejected`() {
        val output = ByteArrayOutputStream()
        PacketTransport(ByteArrayInputStream(byteArrayOf()), output).sendBytes(byteArrayOf(0xc3.toByte(), 0x28))
        assertFailsWith<IOException> { MessageTransport(ByteArrayInputStream(output.toByteArray()), ByteArrayOutputStream()).receive() }
    }

    private fun roundTrip(message: ProtocolMessage, multiple: Boolean = false): ProtocolMessage {
        val output = ByteArrayOutputStream()
        MessageTransport(ByteArrayInputStream(byteArrayOf()), output).send(message)
        val frames = output.toString(Charsets.UTF_8).split('\n').dropLast(1)
        if (multiple) assertTrue(frames.size > 1)
        assertTrue(frames.all { it.toByteArray(Charsets.UTF_8).size + 1 <= PacketConfig.MAX_PACKET_BYTES })
        return MessageTransport(ByteArrayInputStream(output.toByteArray()), ByteArrayOutputStream()).receive()
    }

    companion object {
        private val material by lazy { CertificateGenerator().generate() }
    }
}
