package ua.kpi.rgr.crypto

import ua.kpi.rgr.protocol.ApplicationDataPayload
import ua.kpi.rgr.protocol.ProtocolMessage

object SecureApplicationData {
    const val CLIENT_TO_SERVER_AAD = "APPLICATION_DATA:CLIENT_TO_SERVER"
    const val SERVER_TO_CLIENT_AAD = "APPLICATION_DATA:SERVER_TO_CLIENT"
    const val EXIT_COMMAND = "/exit"

    fun encryptClientToServer(text: String, keys: SessionKeys): ProtocolMessage =
        encrypt(text, keys.clientWriteKey, CLIENT_TO_SERVER_AAD)

    fun decryptClientToServer(message: ProtocolMessage, keys: SessionKeys): String =
        decrypt(message, keys.clientWriteKey, CLIENT_TO_SERVER_AAD)

    fun encryptServerToClient(text: String, keys: SessionKeys): ProtocolMessage =
        encrypt(text, keys.serverWriteKey, SERVER_TO_CLIENT_AAD)

    fun decryptServerToClient(message: ProtocolMessage, keys: SessionKeys): String =
        decrypt(message, keys.serverWriteKey, SERVER_TO_CLIENT_AAD)

    private fun encrypt(text: String, key: ByteArray, aad: String): ProtocolMessage = ApplicationDataPayload.encode(
        AesGcm.encrypt(text.toByteArray(Charsets.UTF_8), key, aad.toByteArray(Charsets.UTF_8)),
    )

    private fun decrypt(message: ProtocolMessage, key: ByteArray, aad: String): String {
        val bytes = AesGcm.decrypt(ApplicationDataPayload.decode(message), key, aad.toByteArray(Charsets.UTF_8))
        return String(bytes, Charsets.UTF_8)
    }
}
