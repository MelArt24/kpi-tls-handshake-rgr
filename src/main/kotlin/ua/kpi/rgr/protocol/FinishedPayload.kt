package ua.kpi.rgr.protocol

import ua.kpi.rgr.crypto.AesGcm
import ua.kpi.rgr.crypto.AesGcmEncrypted
import java.io.IOException
import java.util.Base64

object FinishedPayload {
    const val CLIENT_READY = "CLIENT_READY"
    const val SERVER_READY = "SERVER_READY"

    fun encode(type: MessageType, encrypted: AesGcmEncrypted): ProtocolMessage {
        requireFinishedType(type)
        validate(encrypted)
        return ProtocolMessage(type, mapOf(
            "iv" to Base64.getEncoder().encodeToString(encrypted.iv),
            "ciphertext" to Base64.getEncoder().encodeToString(encrypted.ciphertext),
        ))
    }

    fun decode(message: ProtocolMessage, expectedType: MessageType): AesGcmEncrypted {
        requireFinishedType(expectedType)
        if (message.type != expectedType) throw IOException("Expected $expectedType, received ${message.type}.")
        val encrypted = AesGcmEncrypted(decodeField(message, "iv"), decodeField(message, "ciphertext"))
        validate(encrypted)
        return encrypted
    }

    fun decryptReady(message: ProtocolMessage, expectedType: MessageType, key: ByteArray): String {
        val encrypted = decode(message, expectedType)
        val plaintext = AesGcm.decrypt(encrypted, key, expectedType.name.toByteArray(Charsets.UTF_8))
        val expected = if (expectedType == MessageType.CLIENT_FINISHED) CLIENT_READY else SERVER_READY
        if (!plaintext.contentEquals(expected.toByteArray(Charsets.UTF_8))) {
            throw IOException("$expectedType must contain exactly $expected.")
        }
        return expected
    }

    private fun decodeField(message: ProtocolMessage, field: String): ByteArray {
        val encoded = message.payload[field]
            ?: throw IOException("${message.type} is missing the '$field' payload field.")
        return try {
            Base64.getDecoder().decode(encoded)
        } catch (error: IllegalArgumentException) {
            throw IOException("Invalid Base64 $field in ${message.type}.", error)
        }
    }

    private fun requireFinishedType(type: MessageType) {
        if (type != MessageType.CLIENT_FINISHED && type != MessageType.SERVER_FINISHED) {
            throw IOException("Expected a Finished message type, received $type.")
        }
    }

    private fun validate(encrypted: AesGcmEncrypted) {
        if (encrypted.iv.size != AesGcm.IV_SIZE) throw IOException("Finished IV must be exactly ${AesGcm.IV_SIZE} bytes.")
        if (encrypted.ciphertext.isEmpty()) throw IOException("Finished ciphertext must not be empty.")
    }
}
