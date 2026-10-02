package ua.kpi.rgr.topology.runtime

import ua.kpi.rgr.protocol.PacketConfig
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

object BoundedFrames {
    fun read(input: InputStream): ByteArray? {
        val frame = ByteArrayOutputStream()
        while (true) {
            val byte = input.read()
            if (byte == -1) {
                if (frame.size() == 0) return null
                throw EOFException("Incomplete physical frame: missing LF.")
            }
            if (frame.size() + 1 > PacketConfig.MAX_PACKET_BYTES) {
                throw IOException("Physical frame exceeds ${PacketConfig.MAX_PACKET_BYTES} bytes including LF.")
            }
            frame.write(byte)
            if (byte == 10) {
                if (frame.size() == 1) throw IOException("Empty physical frame.")
                return frame.toByteArray()
            }
        }
    }

    fun write(output: OutputStream, frame: ByteArray) {
        if (frame.size !in 2..PacketConfig.MAX_PACKET_BYTES || frame.last() != 10.toByte() ||
            frame.dropLast(1).contains(10.toByte())) {
            throw IOException("Expected one complete physical frame of at most ${PacketConfig.MAX_PACKET_BYTES} bytes including LF.")
        }
        output.write(frame)
        output.flush()
    }
}

object FrameRelay {
    fun forward(input: InputStream, output: OutputStream, logger: (Int) -> Unit = {}) {
        while (true) {
            val frame = BoundedFrames.read(input) ?: return
            BoundedFrames.write(output, frame)
            logger(frame.size)
        }
    }
}
