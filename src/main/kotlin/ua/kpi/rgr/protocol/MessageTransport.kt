package ua.kpi.rgr.protocol

import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

class MessageTransport(input: InputStream, output: OutputStream, packetLogger: ((String) -> Unit)? = null) {
    private val packets = PacketTransport(input, output, packetLogger)
    private val json = Json { encodeDefaults = true }

    fun send(message: ProtocolMessage) {
        packets.sendBytes(json.encodeToString(message).toByteArray(Charsets.UTF_8))
    }

    fun receive(): ProtocolMessage {
        val bytes = packets.receiveBytes()
        try {
            val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
            return json.decodeFromString<ProtocolMessage>(text)
        } catch (error: CharacterCodingException) {
            throw IOException("Malformed protocol message: invalid UTF-8.", error)
        } catch (error: SerializationException) {
            throw IOException("Malformed protocol message: ${error.message}", error)
        }
    }
}
