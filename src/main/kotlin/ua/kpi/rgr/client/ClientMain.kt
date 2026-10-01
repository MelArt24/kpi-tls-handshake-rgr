package ua.kpi.rgr.client

import ua.kpi.rgr.certificate.CertificateConfig
import ua.kpi.rgr.certificate.CertificateLoader
import ua.kpi.rgr.certificate.ServerCertificatePayload
import ua.kpi.rgr.certificate.ServerCertificateValidator
import ua.kpi.rgr.common.NetworkConfig
import ua.kpi.rgr.crypto.CryptoRandom
import ua.kpi.rgr.crypto.CryptoFingerprint
import ua.kpi.rgr.crypto.SessionKeyDerivation
import ua.kpi.rgr.crypto.PremasterSecret
import ua.kpi.rgr.crypto.RsaKeyExchange
import ua.kpi.rgr.protocol.ClientKeyExchangePayload
import ua.kpi.rgr.protocol.HelloRandomPayload
import ua.kpi.rgr.protocol.MessageTransport
import ua.kpi.rgr.protocol.MessageType
import ua.kpi.rgr.protocol.ProtocolMessage
import java.io.IOException
import java.net.ConnectException
import java.net.Socket
import java.util.Base64

fun main() {
    println("[CLIENT] Connecting to ${NetworkConfig.HOST}:${NetworkConfig.PORT}...")
    try {
        CertificateLoader.requireFile(CertificateConfig.OUTPUT_DIRECTORY.resolve(CertificateConfig.ROOT_CERTIFICATE_FILE))
        Socket(NetworkConfig.HOST, NetworkConfig.PORT).use { socket ->
            println("[CLIENT] Connected.")
            val transport = MessageTransport(socket.getInputStream(), socket.getOutputStream())
            println("\n========== TLS HANDSHAKE SIMULATION ==========\n")
            println("[1] CLIENT_HELLO")
            val clientRandom = CryptoRandom.generateRandomBytes()
            val encodedClientRandom = Base64.getEncoder().encodeToString(clientRandom)
            val request = ProtocolMessage(MessageType.CLIENT_HELLO, mapOf("clientRandom" to encodedClientRandom))
            println("[CLIENT] Generated client random: ${clientRandom.size} bytes")
            println("[CLIENT] clientRandom (Base64): $encodedClientRandom")
            println("[CLIENT] Sending CLIENT_HELLO...")
            transport.send(request)

            val response = transport.receive()
            val serverRandom = HelloRandomPayload.decode(response, MessageType.SERVER_HELLO, "serverRandom")
            println("\n[2] SERVER_HELLO")
            println("[CLIENT] Received SERVER_HELLO")
            println("[CLIENT] serverRandom (Base64): ${response.payload.getValue("serverRandom")}")
            println("[CLIENT] serverRandom length: ${serverRandom.size} bytes")
            println("\n[3] SERVER AUTHENTICATION")
            val serverCertificate = ServerCertificatePayload.decode(response)
            println("[CLIENT] Server certificate received.")
            println("[CLIENT] Subject: ${serverCertificate.subjectX500Principal}")
            println("[CLIENT] Issuer: ${serverCertificate.issuerX500Principal}")
            println("[CLIENT] Serial number: ${serverCertificate.serialNumber}")
            println("[CLIENT] Signature algorithm: ${serverCertificate.sigAlgName}")
            println("[CLIENT] Valid from: ${serverCertificate.notBefore}")
            println("[CLIENT] Valid until: ${serverCertificate.notAfter}")
            println("[CLIENT] Public key algorithm: ${serverCertificate.publicKey.algorithm}")
            val rootCertificate = CertificateLoader.loadRoot()
            println("[CLIENT] Validating server certificate...")
            ServerCertificateValidator.validate(serverCertificate, rootCertificate, NetworkConfig.HOST)
            println("[CLIENT] Certificate validity: OK")
            println("[CLIENT] Trusted Root CA: ${rootCertificate.subjectX500Principal}")
            println("[CLIENT] PKIX certificate path: OK")
            println("[CLIENT] Server certificate usage: OK")
            println("[CLIENT] Server identity ${NetworkConfig.HOST}: OK")
            println("\n========================================")
            println("SERVER AUTHENTICATED")
            println("========================================")

            println("\n[4] CLIENT KEY EXCHANGE")
            val premasterSecret = PremasterSecret.generate()
            println("[CLIENT] Generated premaster secret: ${premasterSecret.size} bytes")
            println("[CLIENT] Encrypting premaster using authenticated server RSA public key...")
            val encryptedPremaster = RsaKeyExchange.encryptPremaster(premasterSecret, serverCertificate.publicKey)
            println("[CLIENT] RSA-OAEP encryption: OK")
            println("[CLIENT] Encrypted premaster length: ${encryptedPremaster.size} bytes")
            println("[CLIENT] Premaster SHA-256: ${CryptoFingerprint.sha256Hex(premasterSecret)}")
            println("[CLIENT] Sending CLIENT_KEY_EXCHANGE...")
            transport.send(ClientKeyExchangePayload.encode(encryptedPremaster))
            println("[CLIENT] CLIENT_KEY_EXCHANGE sent.")

            println("\n[5] SESSION KEY DERIVATION")
            println("[CLIENT] Deriving session keys with HKDF-SHA256...")
            println("[CLIENT] Inputs: premaster ${premasterSecret.size} bytes, clientRandom ${clientRandom.size} bytes, serverRandom ${serverRandom.size} bytes")
            val sessionKeys = SessionKeyDerivation.derive(premasterSecret, clientRandom, serverRandom)
            println("[CLIENT] clientWriteKey derived: ${sessionKeys.clientWriteKey.size} bytes")
            println("[CLIENT] serverWriteKey derived: ${sessionKeys.serverWriteKey.size} bytes")
            println("[CLIENT] clientWriteKey SHA-256: ${CryptoFingerprint.sha256Hex(sessionKeys.clientWriteKey)}")
            println("[CLIENT] serverWriteKey SHA-256: ${CryptoFingerprint.sha256Hex(sessionKeys.serverWriteKey)}")
            println("[CLIENT] Session key derivation completed.")
        }
        println("[CLIENT] Connection closed.")
    } catch (error: ConnectException) {
        System.err.println("[CLIENT] Could not connect. Start ServerMain first. Details: ${error.message}")
    } catch (error: IOException) {
        System.err.println("[CLIENT] Network or protocol error: ${error.message}")
    }
}
