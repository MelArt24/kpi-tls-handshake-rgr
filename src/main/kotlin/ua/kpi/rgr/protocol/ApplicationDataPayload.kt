package ua.kpi.rgr.protocol

import ua.kpi.rgr.crypto.AesGcm
import ua.kpi.rgr.crypto.AesGcmEncrypted
import java.io.IOException
import java.util.Base64

object ApplicationDataPayload {
    fun encode(encrypted: AesGcmEncrypted): ProtocolMessage {
        validate(encrypted)
        return ProtocolMessage(MessageType.APPLICATION_DATA, mapOf(
            "iv" to Base64.getEncoder().encodeToString(encrypted.iv),
            "ciphertext" to Base64.getEncoder().encodeToString(encrypted.ciphertext),
        ))
    }

    fun decode(message: ProtocolMessage): AesGcmEncrypted {
        if (message.type != MessageType.APPLICATION_DATA) {
            throw IOException("Expected APPLICATION_DATA, received ${message.type}.")
        }
        val encrypted = AesGcmEncrypted(decodeField(message, "iv"), decodeField(message, "ciphertext"))
        validate(encrypted)
        return encrypted
    }

    private fun decodeField(message: ProtocolMessage, field: String): ByteArray {
        val encoded = message.payload[field]
            ?: throw IOException("APPLICATION_DATA is missing the '$field' payload field.")
        return try {
            Base64.getDecoder().decode(encoded)
        } catch (error: IllegalArgumentException) {
            throw IOException("Invalid Base64 $field in APPLICATION_DATA.", error)
        }
    }

    private fun validate(encrypted: AesGcmEncrypted) {
        if (encrypted.iv.size != AesGcm.IV_SIZE) throw IOException("Application data IV must be exactly ${AesGcm.IV_SIZE} bytes.")
        if (encrypted.ciphertext.size < AesGcm.TAG_BITS / 8) {
            throw IOException("Application data ciphertext must include the 128-bit GCM tag.")
        }
    }
}
