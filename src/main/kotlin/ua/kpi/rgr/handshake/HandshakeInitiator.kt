package ua.kpi.rgr.handshake

import ua.kpi.rgr.certificate.ServerCertificatePayload
import ua.kpi.rgr.certificate.ServerCertificateValidator
import ua.kpi.rgr.crypto.CryptoRandom
import ua.kpi.rgr.crypto.AesGcm
import ua.kpi.rgr.crypto.CryptoFingerprint
import ua.kpi.rgr.crypto.SessionKeyDerivation
import ua.kpi.rgr.crypto.PremasterSecret
import ua.kpi.rgr.crypto.RsaKeyExchange
import ua.kpi.rgr.protocol.ClientKeyExchangePayload
import ua.kpi.rgr.protocol.FinishedPayload
import ua.kpi.rgr.protocol.HelloRandomPayload
import ua.kpi.rgr.protocol.MessageTransport
import ua.kpi.rgr.protocol.MessageType
import ua.kpi.rgr.protocol.ProtocolMessage
import java.util.Base64
import java.security.cert.X509Certificate
import ua.kpi.rgr.session.EstablishedSecureSession
import ua.kpi.rgr.session.SessionRole

class HandshakeInitiator(private val logger: (String) -> Unit = {}) {
    fun establish(
        transport: MessageTransport,
        trustedRoot: X509Certificate,
        expectedIdentity: String,
    ): EstablishedSecureSession {
        logger("\n========== TLS HANDSHAKE SIMULATION ==========\n")
        logger("[1] CLIENT_HELLO")
        val clientRandom = CryptoRandom.generateRandomBytes()
        val encodedClientRandom = Base64.getEncoder().encodeToString(clientRandom)
        val request = ProtocolMessage(MessageType.CLIENT_HELLO, mapOf("clientRandom" to encodedClientRandom))
        logger("[CLIENT] Generated client random: ${clientRandom.size} bytes")
        logger("[CLIENT] clientRandom (Base64): $encodedClientRandom")
        logger("[CLIENT] Sending CLIENT_HELLO...")
        transport.send(request)

        val response = transport.receive()
        val serverRandom = HelloRandomPayload.decode(response, MessageType.SERVER_HELLO, "serverRandom")
        logger("\n[2] SERVER_HELLO")
        logger("[CLIENT] Received SERVER_HELLO")
        logger("[CLIENT] serverRandom (Base64): ${response.payload.getValue("serverRandom")}")
        logger("[CLIENT] serverRandom length: ${serverRandom.size} bytes")
        logger("\n[3] SERVER AUTHENTICATION")
        val serverCertificate = ServerCertificatePayload.decode(response)
        logger("[CLIENT] Server certificate received.")
        logger("[CLIENT] Subject: ${serverCertificate.subjectX500Principal}")
        logger("[CLIENT] Issuer: ${serverCertificate.issuerX500Principal}")
        logger("[CLIENT] Serial number: ${serverCertificate.serialNumber}")
        logger("[CLIENT] Signature algorithm: ${serverCertificate.sigAlgName}")
        logger("[CLIENT] Valid from: ${serverCertificate.notBefore}")
        logger("[CLIENT] Valid until: ${serverCertificate.notAfter}")
        logger("[CLIENT] Public key algorithm: ${serverCertificate.publicKey.algorithm}")

        logger("[CLIENT] Validating server certificate...")
        ServerCertificateValidator.validate(serverCertificate, trustedRoot, expectedIdentity)
        logger("[CLIENT] Certificate validity: OK")
        logger("[CLIENT] Trusted Root CA: ${trustedRoot.subjectX500Principal}")
        logger("[CLIENT] PKIX certificate path: OK")
        logger("[CLIENT] Server certificate usage: OK")
        logger("[CLIENT] Server identity ${expectedIdentity}: OK")
        logger("\n========================================")
        logger("SERVER AUTHENTICATED")
        logger("========================================")

        logger("\n[4] CLIENT KEY EXCHANGE")
        val premasterSecret = PremasterSecret.generate()
        logger("[CLIENT] Generated premaster secret: ${premasterSecret.size} bytes")
        logger("[CLIENT] Encrypting premaster using authenticated server RSA public key...")
        val encryptedPremaster = RsaKeyExchange.encryptPremaster(premasterSecret, serverCertificate.publicKey)
        logger("[CLIENT] RSA-OAEP encryption: OK")
        logger("[CLIENT] Encrypted premaster length: ${encryptedPremaster.size} bytes")
        logger("[CLIENT] Premaster SHA-256: ${CryptoFingerprint.sha256Hex(premasterSecret)}")
        logger("[CLIENT] Sending CLIENT_KEY_EXCHANGE...")
        transport.send(ClientKeyExchangePayload.encode(encryptedPremaster))
        logger("[CLIENT] CLIENT_KEY_EXCHANGE sent.")

        logger("\n[5] SESSION KEY DERIVATION")
        logger("[CLIENT] Deriving session keys with HKDF-SHA256...")
        logger("[CLIENT] Inputs: premaster ${premasterSecret.size} bytes, clientRandom ${clientRandom.size} bytes, serverRandom ${serverRandom.size} bytes")
        val sessionKeys = SessionKeyDerivation.derive(premasterSecret, clientRandom, serverRandom)
        logger("[CLIENT] clientWriteKey derived: ${sessionKeys.clientWriteKey.size} bytes")
        logger("[CLIENT] serverWriteKey derived: ${sessionKeys.serverWriteKey.size} bytes")
        logger("[CLIENT] clientWriteKey SHA-256: ${CryptoFingerprint.sha256Hex(sessionKeys.clientWriteKey)}")
        logger("[CLIENT] serverWriteKey SHA-256: ${CryptoFingerprint.sha256Hex(sessionKeys.serverWriteKey)}")
        logger("[CLIENT] Session key derivation completed.")

        logger("\n[6] ENCRYPTED HANDSHAKE CONFIRMATION")
        logger("[CLIENT] Encrypting CLIENT_READY with clientWriteKey...")
        val clientFinished = AesGcm.encrypt(
            FinishedPayload.CLIENT_READY.toByteArray(Charsets.UTF_8),
            sessionKeys.clientWriteKey,
            MessageType.CLIENT_FINISHED.name.toByteArray(Charsets.UTF_8),
        )
        logger("[CLIENT] Algorithm: AES-256-GCM")
        logger("[CLIENT] IV length: ${clientFinished.iv.size} bytes")
        logger("[CLIENT] Sending CLIENT_FINISHED...")
        transport.send(FinishedPayload.encode(MessageType.CLIENT_FINISHED, clientFinished))

        val serverFinished = transport.receive()
        logger("[CLIENT] Decrypting SERVER_FINISHED with serverWriteKey...")
        val serverReady = FinishedPayload.decryptReady(serverFinished, MessageType.SERVER_FINISHED, sessionKeys.serverWriteKey)
        logger("[CLIENT] Received SERVER_FINISHED")
        logger("[CLIENT] AES-GCM authentication: OK")
        logger("[CLIENT] Decrypted confirmation: $serverReady")
        logger("[CLIENT] Server readiness confirmed.")
        logger("\n========================================")
        logger("EDUCATIONAL TLS-LIKE HANDSHAKE COMPLETED")
        logger("SECURE SESSION ESTABLISHED")
        logger("========================================")

        return EstablishedSecureSession(transport, sessionKeys, SessionRole.INITIATOR)
    }
}
