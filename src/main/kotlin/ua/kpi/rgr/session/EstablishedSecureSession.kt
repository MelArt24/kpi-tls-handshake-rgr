package ua.kpi.rgr.session

import ua.kpi.rgr.crypto.SecureApplicationData
import ua.kpi.rgr.crypto.SessionKeys
import ua.kpi.rgr.protocol.MessageTransport

class EstablishedSecureSession internal constructor(
    private val transport: MessageTransport,
    sessionKeys: SessionKeys,
    val role: SessionRole,
) {
    private val keys = SessionKeys(sessionKeys.clientWriteKey.copyOf(), sessionKeys.serverWriteKey.copyOf())

    fun sendText(text: String) {
        val message = when (role) {
            SessionRole.INITIATOR -> SecureApplicationData.encryptClientToServer(text, keys)
            SessionRole.RESPONDER -> SecureApplicationData.encryptServerToClient(text, keys)
        }
        transport.send(message)
    }

    fun receiveText(): String {
        val message = transport.receive()
        return when (role) {
            SessionRole.INITIATOR -> SecureApplicationData.decryptServerToClient(message, keys)
            SessionRole.RESPONDER -> SecureApplicationData.decryptClientToServer(message, keys)
        }
    }
}
