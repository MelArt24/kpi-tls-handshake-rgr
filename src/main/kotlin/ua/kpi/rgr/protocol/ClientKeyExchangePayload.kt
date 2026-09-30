package ua.kpi.rgr.protocol

import java.io.IOException
import java.util.Base64

object ClientKeyExchangePayload {
    const val FIELD = "encryptedPremaster"

    fun encode(ciphertext: ByteArray): ProtocolMessage {
        if (ciphertext.isEmpty()) throw IOException("Encrypted premaster must not be empty.")
        return ProtocolMessage(MessageType.CLIENT_KEY_EXCHANGE, mapOf(FIELD to Base64.getEncoder().encodeToString(ciphertext)))
    }

    fun decode(message: ProtocolMessage): ByteArray {
        if (message.type != MessageType.CLIENT_KEY_EXCHANGE) {
            throw IOException("Expected CLIENT_KEY_EXCHANGE, received ${message.type}.")
        }
        val encoded = message.payload[FIELD]
            ?: throw IOException("CLIENT_KEY_EXCHANGE is missing the '$FIELD' payload field.")
        val ciphertext = try {
            Base64.getDecoder().decode(encoded)
        } catch (error: IllegalArgumentException) {
            throw IOException("Invalid Base64 encryptedPremaster in CLIENT_KEY_EXCHANGE.", error)
        }
        if (ciphertext.isEmpty()) throw IOException("Encrypted premaster must not be empty.")
        return ciphertext
    }
}
