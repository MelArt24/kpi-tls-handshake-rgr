package ua.kpi.rgr.protocol

import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.Base64
import java.util.UUID

class PacketTransport(
    input: InputStream,
    output: OutputStream,
    private val logger: ((String) -> Unit)? = null,
) {
    private val input = input.buffered()
    private val output = output.buffered()
    private val json = Json { encodeDefaults = true }

    fun sendBytes(bytes: ByteArray) {
        if (bytes.isEmpty()) throw IOException("Logical message bytes must not be empty.")
        val messageId = UUID.randomUUID().toString()
        var chunkSize = minOf(bytes.size, PacketConfig.MAX_PACKET_BYTES)
        var frames: List<ByteArray>
        while (true) {
            val count = (bytes.size - 1) / chunkSize + 1
            frames = (0 until count).map { index ->
                val start = index * chunkSize
                val chunk = bytes.copyOfRange(start, start + minOf(chunkSize, bytes.size - start))
                val packet = RadioPacket(messageId, index, count, Base64.getEncoder().encodeToString(chunk))
                (json.encodeToString(packet) + "\n").toByteArray(Charsets.UTF_8)
            }
            if (frames.all { it.size <= PacketConfig.MAX_PACKET_BYTES }) break
            chunkSize--
            if (chunkSize == 0) throw IOException("Packet metadata cannot fit the physical packet limit.")
        }
        frames.forEachIndexed { index, frame ->
            output.write(frame)
            logger?.invoke("[PACKET] SEND message $messageId fragment ${index + 1}/${frames.size}, ${frame.size} bytes")
        }
        output.flush()
        logger?.invoke("[PACKET] Sent logical message: ${bytes.size} bytes, ${frames.size} packets, max ${frames.maxOf { it.size }} bytes")
    }

    fun receiveBytes(): ByteArray {
        val reassembled = ByteArrayOutputStream()
        var messageId: String? = null
        var fragmentCount = 0
        var expectedIndex = 0
        var maximumSize = 0
        do {
            val frame = try {
                readFrame()
            } catch (error: EOFException) {
                if (expectedIndex > 0) {
                    throw EOFException("Incomplete fragmented message: received $expectedIndex/$fragmentCount packets.").apply { initCause(error) }
                }
                throw error
            }
            val packet = try {
                json.decodeFromString<RadioPacket>(frame.toString(Charsets.UTF_8))
            } catch (error: SerializationException) {
                throw IOException("Malformed packet JSON: ${error.message}", error)
            }
            if (packet.messageId.isBlank()) throw IOException("Packet messageId must not be blank.")
            if (packet.fragmentCount < 1) throw IOException("Packet fragmentCount must be at least 1.")
            if (packet.fragmentIndex < 0 || packet.fragmentIndex >= packet.fragmentCount) {
                throw IOException("Packet fragmentIndex is outside fragmentCount.")
            }
            if (expectedIndex == 0) {
                messageId = packet.messageId
                fragmentCount = packet.fragmentCount
            }
            if (packet.messageId != messageId) throw IOException("Inconsistent packet messageId in fragmented message.")
            if (packet.fragmentCount != fragmentCount) throw IOException("Inconsistent packet fragmentCount in fragmented message.")
            if (packet.fragmentIndex != expectedIndex) {
                throw IOException("Expected fragment index $expectedIndex, received ${packet.fragmentIndex}; missing, duplicate or out-of-order packet.")
            }
            val chunk = try {
                Base64.getDecoder().decode(packet.payload)
            } catch (error: IllegalArgumentException) {
                throw IOException("Invalid Base64 packet payload.", error)
            }
            reassembled.write(chunk)
            maximumSize = maxOf(maximumSize, frame.size + 1)
            logger?.invoke("[PACKET] RECEIVE message $messageId fragment ${expectedIndex + 1}/$fragmentCount, ${frame.size + 1} bytes")
            expectedIndex++
        } while (expectedIndex < fragmentCount)
        if (reassembled.size() == 0) throw IOException("Reassembled logical message must not be empty.")
        logger?.invoke("[PACKET] Reassembled logical message: ${reassembled.size()} bytes from $fragmentCount packets, max $maximumSize bytes")
        return reassembled.toByteArray()
    }

    private fun readFrame(): ByteArray {
        val frame = ByteArrayOutputStream()
        while (true) {
            val next = input.read()
            if (next == -1) {
                if (frame.size() == 0) throw EOFException("Connection closed before receiving a packet.")
                throw EOFException("Incomplete physical packet: missing newline delimiter.")
            }
            if (frame.size() + 1 > PacketConfig.MAX_PACKET_BYTES) {
                throw IOException("Physical packet exceeds ${PacketConfig.MAX_PACKET_BYTES} bytes including newline.")
            }
            if (next == 10) return frame.toByteArray()
            frame.write(next)
        }
    }
}
