package ua.kpi.rgr.protocol

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class PacketTransportTest {
    @Test
    fun `exact wire frames fit limit for tiny medium and large byte messages`() {
        for (size in listOf(1, 500, 20000)) {
            val bytes = ByteArray(size) { it.toByte() }
            val wire = send(bytes)
            val lines = wire.toString(Charsets.UTF_8).split('\n').dropLast(1)
            assertEquals(10, wire.last().toInt())
            assertTrue(lines.all { it.toByteArray(Charsets.UTF_8).size + 1 <= PacketConfig.MAX_PACKET_BYTES })
            val packets = lines.map { Json.decodeFromString<RadioPacket>(it) }
            assertEquals(1, packets.map { it.messageId }.toSet().size)
            assertEquals(packets.indices.toList(), packets.map { it.fragmentIndex })
            assertTrue(packets.all { it.fragmentCount == packets.size })
            if (size > 256) assertTrue(packets.size > 1)
            assertContentEquals(bytes, receive(wire))
        }
    }

    @Test
    fun `UTF8 fragment boundaries preserve exact original bytes`() {
        val bytes = "Привіт! 👋 Як справи?\n".repeat(100).toByteArray(Charsets.UTF_8)
        assertContentEquals(bytes, receive(send(bytes)))
    }

    @Test
    fun `successive sends have distinct IDs and reassemble separately`() {
        val output = ByteArrayOutputStream()
        val sender = PacketTransport(ByteArrayInputStream(byteArrayOf()), output)
        sender.sendBytes(byteArrayOf(1))
        sender.sendBytes(byteArrayOf(2))
        val packets = output.toString(Charsets.UTF_8).lineSequence().filter { it.isNotEmpty() }.map { Json.decodeFromString<RadioPacket>(it) }.toList()
        assertEquals(2, packets.map { it.messageId }.toSet().size)
        val receiver = PacketTransport(ByteArrayInputStream(output.toByteArray()), ByteArrayOutputStream())
        assertContentEquals(byteArrayOf(1), receiver.receiveBytes())
        assertContentEquals(byteArrayOf(2), receiver.receiveBytes())
    }

    @Test
    fun `malformed packet JSON and Base64 fail clearly`() {
        val jsonError = assertFailsWith<IOException> { receive("not JSON\n".toByteArray()) }
        assertTrue(jsonError.message.orEmpty().contains("Malformed packet JSON"))
        val base64Error = assertFailsWith<IOException> { receive(frames(packet().copy(payload = "%%%"))) }
        assertTrue(base64Error.message.orEmpty().contains("Base64"))
    }

    @Test
    fun `invalid basic metadata is rejected`() {
        for (invalid in listOf(
            packet().copy(messageId = " "), packet().copy(fragmentIndex = -1),
            packet().copy(fragmentIndex = 1), packet().copy(fragmentCount = 0),
        )) assertFailsWith<IOException> { receive(frames(invalid)) }
    }

    @Test
    fun `inconsistent ID count missing duplicate and reordered indexes fail`() {
        val first = packet().copy(fragmentCount = 3)
        val second = first.copy(fragmentIndex = 1)
        val third = first.copy(fragmentIndex = 2)
        for (sequence in listOf(
            listOf(first, second.copy(messageId = "other")),
            listOf(first, second.copy(fragmentCount = 2)),
            listOf(first, third), listOf(first, first), listOf(second, first),
        )) assertFailsWith<IOException> { receive(frames(*sequence.toTypedArray())) }
    }

    @Test
    fun `EOF before first packet and during reassembly is clear`() {
        val before = assertFailsWith<EOFException> { receive(byteArrayOf()) }
        assertTrue(before.message.orEmpty().contains("Connection closed"))
        val during = assertFailsWith<EOFException> { receive(frames(packet().copy(fragmentCount = 2))) }
        assertTrue(during.message.orEmpty().contains("Incomplete fragmented message"))
        assertFailsWith<EOFException> { receive(frames(packet()).dropLast(1).toByteArray()) }
    }

    @Test
    fun `physical size counts UTF8 metadata and newline`() {
        // Use measured padding to reach exactly MAX_PACKET_BYTES, without relying on field ordering.
        val initial = frames(packet())
        val padded = packet().copy(messageId = "x".repeat(1 + PacketConfig.MAX_PACKET_BYTES - initial.size))
        assertEquals(PacketConfig.MAX_PACKET_BYTES, frames(padded).size)
        assertContentEquals(byteArrayOf(1), receive(frames(padded)))
        assertFailsWith<IOException> { receive(frames(padded.copy(messageId = padded.messageId + "x"))) }
        assertFailsWith<IOException> { receive(frames(packet().copy(messageId = "ї".repeat(100)))) }
    }

    @Test
    fun `empty logical bytes are rejected on send and receive`() {
        assertFailsWith<IOException> { send(byteArrayOf()) }
        assertFailsWith<IOException> { receive(frames(packet().copy(payload = ""))) }
    }

    private fun packet() = RadioPacket("x", 0, 1, Base64.getEncoder().encodeToString(byteArrayOf(1)))
    private fun frames(vararg packets: RadioPacket) = packets.joinToString("", transform = { Json.encodeToString(it) + "\n" }).toByteArray(Charsets.UTF_8)
    private fun send(bytes: ByteArray): ByteArray {
        val output = ByteArrayOutputStream()
        PacketTransport(ByteArrayInputStream(byteArrayOf()), output).sendBytes(bytes)
        return output.toByteArray()
    }
    private fun receive(wire: ByteArray) = PacketTransport(ByteArrayInputStream(wire), ByteArrayOutputStream()).receiveBytes()
}
