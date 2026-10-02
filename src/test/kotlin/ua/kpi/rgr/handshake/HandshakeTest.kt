package ua.kpi.rgr.handshake

import ua.kpi.rgr.certificate.CertificateGenerator
import ua.kpi.rgr.certificate.ServerCredentials
import ua.kpi.rgr.certificate.NodeCredentialsLoader
import ua.kpi.rgr.topology.NodeDirectory
import ua.kpi.rgr.topology.NodeId
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import ua.kpi.rgr.protocol.MessageTransport
import ua.kpi.rgr.protocol.PacketConfig
import ua.kpi.rgr.protocol.RadioPacket
import kotlinx.serialization.json.Json
import ua.kpi.rgr.session.EstablishedSecureSession
import ua.kpi.rgr.session.SessionRole
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.IOException
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.cert.X509Certificate
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class HandshakeTest {
    @TempDir
    lateinit var directory: Path
    private val initiator = HandshakeInitiator()
    private val responder = HandshakeResponder()

    @Test
    fun `A1 to B2 and reversed roles authenticate node identities and exchange text`() {
        val generator = CertificateGenerator()
        generator.saveNodes(generator.generateNodes(), directory)
        val root = NodeCredentialsLoader.loadRoot(directory)
        for ((from, to) in listOf(NodeId.A1 to NodeId.B2, NodeId.B2 to NodeId.A1)) {
            Connection().use { connection ->
                val (left, right) = connection.establish(root, NodeCredentialsLoader.load(to, directory),
                    NodeDirectory.config(to).certificateIdentity)
                left.sendText("Привіт $to")
                assertEquals("Привіт $to", right.receiveText())
                right.sendText("Привіт $from")
                assertEquals("Привіт $from", left.receiveText())
                val frames = (connection.captured.toString(Charsets.UTF_8) +
                    connection.responderCaptured.toString(Charsets.UTF_8)).split('\n').dropLast(1)
                assertTrue(frames.all { it.toByteArray(Charsets.UTF_8).size + 1 <= PacketConfig.MAX_PACKET_BYTES })
                val helloPacket = Json.decodeFromString<RadioPacket>(connection.responderCaptured.toString(Charsets.UTF_8).substringBefore('\n'))
                assertTrue(helloPacket.fragmentCount > 1, "Node SERVER_HELLO certificate must fragment.")
            }
        }
    }

    @Test
    fun `real handshake establishes directional sessions and fragmented Ukrainian chat`() {
        Connection().use { connection ->
            val (left, right) = connection.establish()
            assertEquals(SessionRole.INITIATOR, left.role)
            assertEquals(SessionRole.RESPONDER, right.role)
            left.sendText("Привіт")
            assertEquals("Привіт", right.receiveText())
            right.sendText("Вітаю")
            assertEquals("Вітаю", left.receiveText())
            val longText = "Довге українське повідомлення!\n".repeat(50)
            left.sendText(longText)
            assertEquals(longText, right.receiveText())
            left.sendText("/exit")
            assertEquals("/exit", right.receiveText())
            val frames = connection.captured.toString(Charsets.UTF_8).split('\n').dropLast(1)
            assertTrue(frames.size > 10)
            assertTrue(frames.all { it.toByteArray(Charsets.UTF_8).size + 1 <= PacketConfig.MAX_PACKET_BYTES })
        }
    }

    @Test
    fun `reused handshake components produce independent sessions`() {
        Connection().use { first ->
            Connection().use { second ->
                val (initiatorA, responderA) = first.establish()
                val (initiatorB, responderB) = second.establish()
                first.captured.reset()
                initiatorA.sendText("Session A only")
                assertEquals("Session A only", responderA.receiveText())
                initiatorB.sendText("Session B only")
                assertEquals("Session B only", responderB.receiveText())
                // Replay the complete captured packet stream without exposing either session's keys.
                second.client.getOutputStream().write(first.captured.toByteArray())
                second.client.getOutputStream().flush()
                assertFailsWith<IOException> { responderB.receiveText() }
            }
        }
    }

    @Test
    fun `unrelated root aborts handshake before returning a session`() {
        val unrelatedRoot = CertificateGenerator().generate().rootCertificate
        Connection().use { connection ->
            assertFailsWith<IOException> { connection.establish(unrelatedRoot) }
        }
    }

    private inner class Connection : Closeable {
        val client: Socket
        private val server: Socket
        val captured = ByteArrayOutputStream()
        val responderCaptured = ByteArrayOutputStream()
        private val executor = Executors.newSingleThreadExecutor()

        init {
            ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { listener ->
                client = Socket(listener.inetAddress, listener.localPort)
                server = listener.accept()
            }
            client.soTimeout = 5000
            server.soTimeout = 5000
        }

        fun establish(
            root: X509Certificate = material.rootCertificate,
            credentials: ServerCredentials = ServerCredentials(material.serverKeyPair.private, material.serverCertificate,
                listOf(material.serverCertificate, material.rootCertificate)),
            identity: String = "localhost",
        ): Pair<EstablishedSecureSession, EstablishedSecureSession> {
            val output = client.getOutputStream()
            val recording = object : OutputStream() {
                override fun write(value: Int) {
                    output.write(value)
                    captured.write(value)
                }

                override fun write(bytes: ByteArray, offset: Int, length: Int) {
                    output.write(bytes, offset, length)
                    captured.write(bytes, offset, length)
                }

                override fun flush() = output.flush()
            }
            val pending = executor.submit<EstablishedSecureSession> {
                responder.establish(
                    MessageTransport(server.getInputStream(), object : OutputStream() {
                        private val responderOutput = server.getOutputStream()
                        override fun write(value: Int) {
                            responderOutput.write(value)
                            responderCaptured.write(value)
                        }
                        override fun write(bytes: ByteArray, offset: Int, length: Int) {
                            responderOutput.write(bytes, offset, length)
                            responderCaptured.write(bytes, offset, length)
                        }
                        override fun flush() = responderOutput.flush()
                    }),
                    credentials,
                )
            }
            try {
                val session = initiator.establish(MessageTransport(client.getInputStream(), recording), root, identity)
                return session to pending.get(10, TimeUnit.SECONDS)
            } catch (error: Exception) {
                client.close()
                server.close()
                pending.cancel(true)
                throw error
            }
        }

        override fun close() {
            try {
                client.close()
            } finally {
                server.close()
                executor.shutdownNow()
                check(executor.awaitTermination(5, TimeUnit.SECONDS)) { "Handshake test worker did not terminate." }
            }
        }
    }

    companion object {
        private val material by lazy { CertificateGenerator().generate() }
    }
}
