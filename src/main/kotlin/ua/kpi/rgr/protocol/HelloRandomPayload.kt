package ua.kpi.rgr.protocol

import ua.kpi.rgr.crypto.CryptoRandom
import java.io.IOException
import java.util.Base64

object HelloRandomPayload {
    fun decode(message: ProtocolMessage, expectedType: MessageType, field: String): ByteArray {
        if (message.type != expectedType) {
            throw IOException("Expected $expectedType, received ${message.type}.")
        }
        val encoded = message.payload[field]
            ?: throw IOException("$expectedType is missing the '$field' payload field.")
        val bytes = try {
            Base64.getDecoder().decode(encoded)
        } catch (error: IllegalArgumentException) {
            throw IOException("Invalid Base64 $field in $expectedType.", error)
        }
        if (bytes.size != CryptoRandom.RANDOM_SIZE) {
            throw IOException("$expectedType $field must be exactly ${CryptoRandom.RANDOM_SIZE} bytes.")
        }
        return bytes
    }
}
