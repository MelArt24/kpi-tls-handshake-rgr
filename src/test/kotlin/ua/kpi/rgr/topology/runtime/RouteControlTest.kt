package ua.kpi.rgr.topology.runtime

import ua.kpi.rgr.protocol.PacketConfig
import ua.kpi.rgr.protocol.PacketTransport
import ua.kpi.rgr.topology.NodeId
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class RouteControlTest {
    private val open = RouteControlFrame(RouteControlType.OPEN, UUID.randomUUID().toString(), NodeId.A1, NodeId.B2, NodeId.A1)

    @Test
    fun `OPEN and READY round trip under the complete physical limit without stealing next bytes`() {
        for (type in RouteControlType.entries) {
            val frame = open.copy(type = type)
            val output = ByteArrayOutputStream()
            RouteControlCodec.write(output, frame)
            assertTrue(output.size() <= PacketConfig.MAX_PACKET_BYTES)
            val input = ByteArrayInputStream(output.toByteArray() + "next\n".toByteArray())
            assertEquals(frame, RouteControlCodec.read(input))
            assertContentEquals("next\n".toByteArray(), input.readBytes())
        }
    }

    @Test
    fun `malformed control input and invalid metadata are rejected`() {
        val output = ByteArrayOutputStream()
        RouteControlCodec.write(output, open)
        val valid = output.toString(Charsets.UTF_8)
        for (text in listOf("{broken}\n", valid.replace("A1", "UNKNOWN"), valid.replace("OPEN", "UNKNOWN"),
            valid.replace(open.routeId, " "), "x".repeat(256) + "\n", valid.trimEnd())) {
            assertFailsWith<IOException> { RouteControlCodec.read(ByteArrayInputStream(text.toByteArray())) }
        }
        assertFailsWith<IOException> { RouteControlCodec.write(output, open.copy(source = NodeId.B2)) }
        assertFailsWith<IOException> { RouteControlCodec.write(output, open.copy(routeId = "not-a-uuid")) }
        assertFailsWith<IOException> { RouteSetup.incoming(NodeId.HUB_A, open.copy(type = RouteControlType.READY)) }
    }

    @Test
    fun `canonical next hops and reverse route are validated`() {
        assertEquals(RouteHops(NodeId.A1, NodeId.HUB_B), RouteSetup.incoming(NodeId.HUB_A, open))
        assertEquals(RouteHops(NodeId.HUB_A, NodeId.B2), RouteSetup.incoming(NodeId.HUB_B, open.copy(sender = NodeId.HUB_A)))
        assertEquals(RouteHops(NodeId.HUB_B, null), RouteSetup.incoming(NodeId.B2, open.copy(sender = NodeId.HUB_B)))
        val reverse = open.copy(source = NodeId.B2, destination = NodeId.A1, sender = NodeId.B2)
        assertEquals(RouteHops(NodeId.B2, NodeId.HUB_A), RouteSetup.incoming(NodeId.HUB_B, reverse))
        assertEquals(RouteHops(NodeId.HUB_B, NodeId.A1), RouteSetup.incoming(NodeId.HUB_A, reverse.copy(sender = NodeId.HUB_B)))
        assertEquals(RouteHops(NodeId.HUB_A, null), RouteSetup.incoming(NodeId.A1, reverse.copy(sender = NodeId.HUB_A)))
    }

    @Test
    fun `direct bypass wrong hop off-route node and source OPEN are rejected`() {
        assertFailsWith<IOException> { RouteSetup.incoming(NodeId.B2, open) }
        assertFailsWith<IOException> { RouteSetup.incoming(NodeId.HUB_B, open) }
        assertFailsWith<IOException> { RouteSetup.incoming(NodeId.A2, open) }
        assertFailsWith<IOException> { RouteSetup.incoming(NodeId.A1, open) }
    }

    @Test
    fun `READY must match every route field and downstream sender`() {
        val ready = open.copy(type = RouteControlType.READY, sender = NodeId.HUB_A)
        RouteSetup.ready(ready, open, NodeId.HUB_A)
        for (invalid in listOf(ready.copy(type = RouteControlType.OPEN), ready.copy(routeId = UUID.randomUUID().toString()),
            ready.copy(source = NodeId.A2), ready.copy(destination = NodeId.B1), ready.copy(sender = NodeId.HUB_B))) {
            assertFailsWith<IOException> { RouteSetup.ready(invalid, open, NodeId.HUB_A) }
        }
    }

    @Test
    fun `relay forwards complete RadioPacket frames byte for byte in both directions`() {
        val wire = ByteArrayOutputStream()
        PacketTransport(ByteArrayInputStream(byteArrayOf()), wire).sendBytes(ByteArray(1000) { it.toByte() })
        val forwarded = ByteArrayOutputStream()
        val sizes = mutableListOf<Int>()
        FrameRelay.forward(ByteArrayInputStream(wire.toByteArray()), forwarded) { sizes.add(it) }
        assertContentEquals(wire.toByteArray(), forwarded.toByteArray())
        val back = ByteArrayOutputStream()
        FrameRelay.forward(ByteArrayInputStream(forwarded.toByteArray()), back)
        assertContentEquals(wire.toByteArray(), back.toByteArray())
        assertTrue(sizes.size > 1 && sizes.all { it <= PacketConfig.MAX_PACKET_BYTES })
    }

    @Test
    fun `oversized and incomplete forwarded frames never reach output`() {
        for (wire in listOf("x".repeat(256) + "\n", "missing newline", "\n")) {
            val output = ByteArrayOutputStream()
            assertFailsWith<IOException> { FrameRelay.forward(ByteArrayInputStream(wire.toByteArray()), output) }
            assertEquals(0, output.size())
        }
    }
}
