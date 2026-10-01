package ua.kpi.rgr.server

import ua.kpi.rgr.certificate.ServerCredentialsLoader
import ua.kpi.rgr.certificate.ServerCertificatePayload
import ua.kpi.rgr.common.NetworkConfig
import ua.kpi.rgr.crypto.CryptoRandom
import ua.kpi.rgr.crypto.AesGcm
import ua.kpi.rgr.crypto.SecureApplicationData
import ua.kpi.rgr.crypto.CryptoFingerprint
import ua.kpi.rgr.crypto.SessionKeyDerivation
import ua.kpi.rgr.crypto.RsaKeyExchange
import ua.kpi.rgr.protocol.ClientKeyExchangePayload
import ua.kpi.rgr.protocol.FinishedPayload
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
                val transport = MessageTransport(client.getInputStream(), client.getOutputStream(), ::println)
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

                println("\n[6] ENCRYPTED HANDSHAKE CONFIRMATION")
                val clientFinished = transport.receive()
                println("[SERVER] Decrypting CLIENT_FINISHED with clientWriteKey...")
                val clientReady = FinishedPayload.decryptReady(clientFinished, MessageType.CLIENT_FINISHED, sessionKeys.clientWriteKey)
                println("[SERVER] Received CLIENT_FINISHED")
                println("[SERVER] AES-GCM authentication: OK")
                println("[SERVER] Decrypted confirmation: $clientReady")
                println("[SERVER] Client readiness confirmed.")

                println("[SERVER] Encrypting SERVER_READY with serverWriteKey...")
                val serverFinished = AesGcm.encrypt(
                    FinishedPayload.SERVER_READY.toByteArray(Charsets.UTF_8),
                    sessionKeys.serverWriteKey,
                    MessageType.SERVER_FINISHED.name.toByteArray(Charsets.UTF_8),
                )
                println("[SERVER] Algorithm: AES-256-GCM")
                println("[SERVER] IV length: ${serverFinished.iv.size} bytes")
                println("[SERVER] Sending SERVER_FINISHED...")
                transport.send(FinishedPayload.encode(MessageType.SERVER_FINISHED, serverFinished))
                println("[SERVER] Encrypted handshake confirmation completed.")
                println("[SERVER] Educational secure session established; SERVER_FINISHED sent.")

                val console = System.`in`.bufferedReader(Charsets.UTF_8)
                println("[SERVER] Secure chat started. Reply after each client message; type /exit to close.")
                while (true) {
                    val text = SecureApplicationData.decryptClientToServer(transport.receive(), sessionKeys)
                    if (text == SecureApplicationData.EXIT_COMMAND) {
                        println("[SERVER] Client ended the chat.")
                        break
                    }
                    println("[SERVER] Client: $text")
                    print("[SERVER] You: ")
                    System.out.flush()
                    val reply = console.readLine() ?: SecureApplicationData.EXIT_COMMAND
                    transport.send(SecureApplicationData.encryptServerToClient(reply, sessionKeys))
                    println("[SERVER] Sent encrypted APPLICATION_DATA.")
                    if (reply == SecureApplicationData.EXIT_COMMAND) break
                }
                println("[SERVER] Secure chat closed.")
            }
        }
        println("[SERVER] Connection closed. Server stopped.")
    } catch (error: IOException) {
        System.err.println("[SERVER] Network or protocol error: ${error.message}")
    }
}
