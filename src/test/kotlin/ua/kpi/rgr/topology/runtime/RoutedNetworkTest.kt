package ua.kpi.rgr.topology.runtime

import ua.kpi.rgr.certificate.CertificateGenerator
import ua.kpi.rgr.certificate.GeneratedCertificates
import ua.kpi.rgr.certificate.ServerCredentials
import ua.kpi.rgr.handshake.HandshakeInitiator
import ua.kpi.rgr.handshake.HandshakeResponder
import ua.kpi.rgr.protocol.MessageTransport
import ua.kpi.rgr.protocol.PacketConfig
import ua.kpi.rgr.protocol.PacketTransport
import ua.kpi.rgr.topology.DoubleStarTopology
import ua.kpi.rgr.topology.NodeDirectory
import ua.kpi.rgr.topology.NodeId
import java.io.Closeable
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class RoutedNetworkTest {
    @Test
    fun `all 30 ordered pairs tunnel only through canonical physical neighbors`() {
        Network { _, connection ->
            val packets = PacketTransport(connection.inputStream, connection.outputStream)
            packets.sendBytes(packets.receiveBytes())
        }.use { network ->
            for (source in NodeId.entries) for (destination in NodeId.entries.filter { it != source }) {
                network.operation {
                    network.runtimes.getValue(source).connect(destination).use { connection ->
                        assertEquals(source, connection.source)
                        assertEquals(destination, connection.destination)
                        val packets = PacketTransport(connection.inputStream, connection.outputStream)
                        val bytes = "$source -> $destination".repeat(30).toByteArray()
                        packets.sendBytes(bytes)
                        assertContentEquals(bytes, packets.receiveBytes())
                    }
                }
                network.awaitHandler()
                val route = DoubleStarTopology.findRoute(source, destination)
                for ((from, to) in route.nodes.zipWithNext()) {
                    assertTrue(network.logs.any { it.contains("[$from] [ROUTE] Physical connection $from -> $to") })
                }
            }
            assertEquals(30, network.delivered.size)
            assertTrue(network.delivered.all { (local, destination) -> local == destination })
            assertTrue(network.errors.isEmpty())
            for (line in network.logs.filter { "Physical connection" in it }) {
                val pair = Regex("Physical connection (\\w+) -> (\\w+)").find(line)!!
                assertTrue(DoubleStarTopology.areNeighbors(NodeId.valueOf(pair.groupValues[1]), NodeId.valueOf(pair.groupValues[2])))
            }
        }
    }

    @Test
    fun `routed real handshakes authenticate remote identities in both roles and exchange fragmented Ukrainian chat`() {
        val longText = "Привіт через Double Star!\n".repeat(80)
        Network { local, connection ->
            val leaf = material.nodes.getValue(local)
            val session = HandshakeResponder().establish(
                MessageTransport(connection.inputStream, connection.outputStream), credentials(leaf),
            )
            assertEquals("Привіт через Double Star!", session.receiveText())
            session.sendText("Вітаю, ${connection.source}!")
            assertEquals(longText, session.receiveText())
            session.sendText("Прийнято")
            assertEquals("/exit", session.receiveText())
        }.use { network ->
            for ((source, destination) in listOf(NodeId.A1 to NodeId.B2, NodeId.B2 to NodeId.A1)) {
                network.operation {
                    network.runtimes.getValue(source).connect(destination).use { connection ->
                        val session = HandshakeInitiator().establish(
                            MessageTransport(connection.inputStream, connection.outputStream), material.rootCertificate,
                            NodeDirectory.config(destination).certificateIdentity,
                        )
                        session.sendText("Привіт через Double Star!")
                        assertEquals("Вітаю, $source!", session.receiveText())
                        session.sendText(longText)
                        assertEquals("Прийнято", session.receiveText())
                        session.sendText("/exit")
                        network.awaitHandler()
                    }
                }
            }
            assertEquals(listOf(NodeId.B2 to NodeId.B2, NodeId.A1 to NodeId.A1), network.delivered.toList())
            val forwards = network.logs.filter { "[FORWARD]" in it && "frame" in it }
            assertTrue(forwards.size > 60)
            assertTrue(forwards.all { Regex("frame (\\d+) bytes").find(it)!!.groupValues[1].toInt() <= PacketConfig.MAX_PACKET_BYTES })
            for (hub in listOf(NodeId.HUB_A, NodeId.HUB_B)) {
                assertTrue(forwards.any { it.startsWith("[$hub]") })
            }
            assertTrue(network.errors.isEmpty())
        }
    }

    @Test
    fun `actual direct bypass and malformed oversized forwarded traffic abort without endpoint delivery`() {
        Network { _, connection ->
            val data = BoundedFrames.read(connection.inputStream)
            assertEquals(null, data)
        }.use { network ->
            Socket().use { socket ->
                socket.connect(network.addresses.getValue(NodeId.B2))
                socket.soTimeout = 5000
                RouteControlCodec.write(socket.getOutputStream(), RouteControlFrame(RouteControlType.OPEN,
                    UUID.randomUUID().toString(), NodeId.A1, NodeId.B2, NodeId.A1))
                assertFailsWith<IOException> { RouteControlCodec.read(socket.getInputStream()) }
            }
            assertTrue(network.delivered.isEmpty())
            network.operation {
                network.runtimes.getValue(NodeId.A1).connect(NodeId.B2).use { connection ->
                    connection.outputStream.write(("x".repeat(256) + "\n").toByteArray())
                    connection.outputStream.flush()
                    network.awaitHandler()
                }
            }
            assertTrue(network.logs.any { "exceeds 256" in it })
            assertTrue(network.errors.isEmpty())
        }
    }

    @Test
    fun `closing runtimes unblocks idle routes and stops every listener and worker`() {
        val network = Network { _, connection -> assertEquals(null, BoundedFrames.read(connection.inputStream)) }
        val connection = network.runtimes.getValue(NodeId.A1).connect(NodeId.B2)
        try {
            network.close()
            assertTrue(network.runtimes.keys.all { id ->
                assertFailsWith<IOException> { Socket().use { it.connect(network.addresses.getValue(id), 500) } }
                true
            })
            assertTrue(Thread.getAllStackTraces().keys.none { it.isAlive && it.name.startsWith("rgr-") })
        } finally {
            connection.close()
            network.close()
        }
    }

    private fun credentials(leaf: GeneratedCertificates) = ServerCredentials(
        leaf.serverKeyPair.private, leaf.serverCertificate, listOf(leaf.serverCertificate, leaf.rootCertificate),
    )

    private class Network(handler: (NodeId, RoutedConnection) -> Unit) : Closeable {
        val addresses = ConcurrentHashMap<NodeId, InetSocketAddress>()
        val logs = CopyOnWriteArrayList<String>()
        val delivered = CopyOnWriteArrayList<Pair<NodeId, NodeId>>()
        val errors = LinkedBlockingQueue<Throwable>()
        private val completions = LinkedBlockingQueue<Boolean>()
        private val caller = Executors.newSingleThreadExecutor()
        val runtimes = NodeId.entries.associateWith { id ->
            TopologyNodeRuntime(id, { addresses[it] ?: InetSocketAddress(InetAddress.getLoopbackAddress(), 0) }, { logs.add(it) })
        }

        init {
            try {
                for ((id, runtime) in runtimes) {
                    runtime.start { connection ->
                        delivered.add(id to connection.destination)
                        try { handler(id, connection) } catch (error: Throwable) { errors.add(error) }
                        finally { completions.add(true) }
                    }
                    addresses[id] = runtime.localAddress
                }
            } catch (error: Exception) { close(); throw error }
        }

        fun operation(action: () -> Unit) {
            val future = caller.submit(action)
            try { future.get(20, TimeUnit.SECONDS) } catch (error: Exception) {
                close()
                future.cancel(true)
                throw error
            }
        }

        fun awaitHandler() {
            assertNotNull(completions.poll(10, TimeUnit.SECONDS), "Destination handler did not finish.")
            errors.poll()?.let { throw AssertionError("Endpoint handler failed", it) }
        }

        override fun close() {
            try { runtimes.values.toList().asReversed().forEach { it.close() } }
            finally {
                caller.shutdownNow()
                check(caller.awaitTermination(5, TimeUnit.SECONDS))
            }
        }
    }

    companion object { private val material by lazy { CertificateGenerator().generateNodes() } }
}
