package ua.kpi.rgr.server

import ua.kpi.rgr.certificate.ServerCredentialsLoader
import ua.kpi.rgr.certificate.ServerCertificatePayload
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
import java.net.InetAddress
import java.net.ServerSocket
import java.util.Base64

fun main() {
    try {
        val credentials = ServerCredentialsLoader.load()
        ServerSocket(NetworkConfig.PORT, 1, InetAddress.getByName(NetworkConfig.HOST)).use { server ->
            println("[SERVER] Started on ${NetworkConfig.HOST}:${NetworkConfig.PORT}.")
            println("[SERVER] Waiting for client...")
            server.accept().use { client ->
                println("[SERVER] Client connected: ${client.remoteSocketAddress}")
                val transport = MessageTransport(client.getInputStream(), client.getOutputStream())
                val request = transport.receive()
                val clientRandom = HelloRandomPayload.decode(request, MessageType.CLIENT_HELLO, "clientRandom")
                println("\n========== TLS HANDSHAKE SIMULATION ==========\n")
                println("[1] CLIENT_HELLO")
                println("[SERVER] Received CLIENT_HELLO")
                println("[SERVER] clientRandom (Base64): ${request.payload.getValue("clientRandom")}")
                println("[SERVER] clientRandom length: ${clientRandom.size} bytes")

                println("\n[2] SERVER_HELLO")
                val serverRandom = CryptoRandom.generateRandomBytes()
                val encodedServerRandom = Base64.getEncoder().encodeToString(serverRandom)
                val serverCertificate = credentials.certificate
                println("[SERVER] Loaded server certificate.")
                println("[SERVER] Subject: ${serverCertificate.subjectX500Principal}")
                println("[SERVER] Issuer: ${serverCertificate.issuerX500Principal}")
                println("[SERVER] Adding X.509 certificate to SERVER_HELLO...")
                val response = ProtocolMessage(
                    MessageType.SERVER_HELLO,
                    mapOf(
                        "serverRandom" to encodedServerRandom,
                        ServerCertificatePayload.FIELD to ServerCertificatePayload.encode(serverCertificate),
                    ),
                )
                println("[SERVER] Generated server random: ${serverRandom.size} bytes")
                println("[SERVER] serverRandom (Base64): $encodedServerRandom")
                println("[SERVER] Sending SERVER_HELLO...")
                transport.send(response)
                println("[SERVER] Hello exchange completed.")

                println("\n[4] CLIENT KEY EXCHANGE")
                val keyExchange = transport.receive()
                val encryptedPremaster = ClientKeyExchangePayload.decode(keyExchange)
                println("[SERVER] Received CLIENT_KEY_EXCHANGE")
                println("[SERVER] Encrypted premaster length: ${encryptedPremaster.size} bytes")
                println("[SERVER] Decrypting with server RSA private key...")
                val premasterSecret = RsaKeyExchange.decryptPremaster(encryptedPremaster, credentials.privateKey)
                println("[SERVER] Premaster recovered: ${premasterSecret.size} bytes")
                println("[SERVER] Premaster SHA-256: ${CryptoFingerprint.sha256Hex(premasterSecret)}")
                println("[SERVER] Client key exchange completed.")

                println("\n[5] SESSION KEY DERIVATION")
                println("[SERVER] Deriving session keys with HKDF-SHA256...")
                println("[SERVER] Inputs: premaster ${premasterSecret.size} bytes, clientRandom ${clientRandom.size} bytes, serverRandom ${serverRandom.size} bytes")
                val sessionKeys = SessionKeyDerivation.derive(premasterSecret, clientRandom, serverRandom)
                println("[SERVER] clientWriteKey derived: ${sessionKeys.clientWriteKey.size} bytes")
                println("[SERVER] serverWriteKey derived: ${sessionKeys.serverWriteKey.size} bytes")
                println("[SERVER] clientWriteKey SHA-256: ${CryptoFingerprint.sha256Hex(sessionKeys.clientWriteKey)}")
                println("[SERVER] serverWriteKey SHA-256: ${CryptoFingerprint.sha256Hex(sessionKeys.serverWriteKey)}")
                println("[SERVER] Session key derivation completed.")
            }
        }
        println("[SERVER] Connection closed. Server stopped.")
    } catch (error: IOException) {
        System.err.println("[SERVER] Network or protocol error: ${error.message}")
    }
}
