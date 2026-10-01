package ua.kpi.rgr.handshake

import ua.kpi.rgr.certificate.ServerCertificatePayload
import ua.kpi.rgr.crypto.CryptoRandom
import ua.kpi.rgr.crypto.AesGcm
import ua.kpi.rgr.crypto.CryptoFingerprint
import ua.kpi.rgr.crypto.SessionKeyDerivation
import ua.kpi.rgr.crypto.RsaKeyExchange
import ua.kpi.rgr.protocol.ClientKeyExchangePayload
import ua.kpi.rgr.protocol.FinishedPayload
import ua.kpi.rgr.protocol.HelloRandomPayload
import ua.kpi.rgr.protocol.MessageTransport
import ua.kpi.rgr.protocol.MessageType
import ua.kpi.rgr.protocol.ProtocolMessage
import java.util.Base64
import ua.kpi.rgr.certificate.ServerCredentials
import ua.kpi.rgr.session.EstablishedSecureSession
import ua.kpi.rgr.session.SessionRole

class HandshakeResponder(private val logger: (String) -> Unit = {}) {
    fun establish(
        transport: MessageTransport,
        credentials: ServerCredentials,
    ): EstablishedSecureSession {
        val request = transport.receive()
        val clientRandom = HelloRandomPayload.decode(request, MessageType.CLIENT_HELLO, "clientRandom")
        logger("\n========== TLS HANDSHAKE SIMULATION ==========\n")
        logger("[1] CLIENT_HELLO")
        logger("[SERVER] Received CLIENT_HELLO")
        logger("[SERVER] clientRandom (Base64): ${request.payload.getValue("clientRandom")}")
        logger("[SERVER] clientRandom length: ${clientRandom.size} bytes")

        logger("\n[2] SERVER_HELLO")
        val serverRandom = CryptoRandom.generateRandomBytes()
        val encodedServerRandom = Base64.getEncoder().encodeToString(serverRandom)
        val serverCertificate = credentials.certificate
        logger("[SERVER] Loaded server certificate.")
        logger("[SERVER] Subject: ${serverCertificate.subjectX500Principal}")
        logger("[SERVER] Issuer: ${serverCertificate.issuerX500Principal}")
        logger("[SERVER] Adding X.509 certificate to SERVER_HELLO...")
        val response = ProtocolMessage(
            MessageType.SERVER_HELLO,
            mapOf(
                "serverRandom" to encodedServerRandom,
                ServerCertificatePayload.FIELD to ServerCertificatePayload.encode(serverCertificate),
            ),
        )
        logger("[SERVER] Generated server random: ${serverRandom.size} bytes")
        logger("[SERVER] serverRandom (Base64): $encodedServerRandom")
        logger("[SERVER] Sending SERVER_HELLO...")
        transport.send(response)
        logger("[SERVER] Hello exchange completed.")

        logger("\n[4] CLIENT KEY EXCHANGE")
        val keyExchange = transport.receive()
        val encryptedPremaster = ClientKeyExchangePayload.decode(keyExchange)
        logger("[SERVER] Received CLIENT_KEY_EXCHANGE")
        logger("[SERVER] Encrypted premaster length: ${encryptedPremaster.size} bytes")
        logger("[SERVER] Decrypting with server RSA private key...")
        val premasterSecret = RsaKeyExchange.decryptPremaster(encryptedPremaster, credentials.privateKey)
        logger("[SERVER] Premaster recovered: ${premasterSecret.size} bytes")
        logger("[SERVER] Premaster SHA-256: ${CryptoFingerprint.sha256Hex(premasterSecret)}")
        logger("[SERVER] Client key exchange completed.")

        logger("\n[5] SESSION KEY DERIVATION")
        logger("[SERVER] Deriving session keys with HKDF-SHA256...")
        logger("[SERVER] Inputs: premaster ${premasterSecret.size} bytes, clientRandom ${clientRandom.size} bytes, serverRandom ${serverRandom.size} bytes")
        val sessionKeys = SessionKeyDerivation.derive(premasterSecret, clientRandom, serverRandom)
        logger("[SERVER] clientWriteKey derived: ${sessionKeys.clientWriteKey.size} bytes")
        logger("[SERVER] serverWriteKey derived: ${sessionKeys.serverWriteKey.size} bytes")
        logger("[SERVER] clientWriteKey SHA-256: ${CryptoFingerprint.sha256Hex(sessionKeys.clientWriteKey)}")
        logger("[SERVER] serverWriteKey SHA-256: ${CryptoFingerprint.sha256Hex(sessionKeys.serverWriteKey)}")
        logger("[SERVER] Session key derivation completed.")

        logger("\n[6] ENCRYPTED HANDSHAKE CONFIRMATION")
        val clientFinished = transport.receive()
        logger("[SERVER] Decrypting CLIENT_FINISHED with clientWriteKey...")
        val clientReady = FinishedPayload.decryptReady(clientFinished, MessageType.CLIENT_FINISHED, sessionKeys.clientWriteKey)
        logger("[SERVER] Received CLIENT_FINISHED")
        logger("[SERVER] AES-GCM authentication: OK")
        logger("[SERVER] Decrypted confirmation: $clientReady")
        logger("[SERVER] Client readiness confirmed.")

        logger("[SERVER] Encrypting SERVER_READY with serverWriteKey...")
        val serverFinished = AesGcm.encrypt(
            FinishedPayload.SERVER_READY.toByteArray(Charsets.UTF_8),
            sessionKeys.serverWriteKey,
            MessageType.SERVER_FINISHED.name.toByteArray(Charsets.UTF_8),
        )
        logger("[SERVER] Algorithm: AES-256-GCM")
        logger("[SERVER] IV length: ${serverFinished.iv.size} bytes")
        logger("[SERVER] Sending SERVER_FINISHED...")
        transport.send(FinishedPayload.encode(MessageType.SERVER_FINISHED, serverFinished))
        logger("[SERVER] Encrypted handshake confirmation completed.")
        logger("[SERVER] Educational secure session established; SERVER_FINISHED sent.")

        return EstablishedSecureSession(transport, sessionKeys, SessionRole.RESPONDER)
    }
}
