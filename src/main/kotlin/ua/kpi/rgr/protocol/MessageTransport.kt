package ua.kpi.rgr.protocol

import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

class MessageTransport(input: InputStream, output: OutputStream) {
    private val reader = input.bufferedReader(Charsets.UTF_8)
    private val writer = output.bufferedWriter(Charsets.UTF_8)
    private val json = Json { encodeDefaults = true }

    fun send(message: ProtocolMessage) {
        writer.write(json.encodeToString(message))
        writer.write("\n")
        writer.flush()
    }

    fun receive(): ProtocolMessage {
        val line = reader.readLine()
            ?: throw EOFException("Connection closed before receiving a protocol message.")
        try {
            return json.decodeFromString<ProtocolMessage>(line)
        } catch (error: SerializationException) {
            throw IOException("Malformed protocol message: ${error.message}", error)
        }
    }
}
