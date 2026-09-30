package ua.kpi.rgr.server

import ua.kpi.rgr.certificate.CertificateConfig
import ua.kpi.rgr.certificate.CertificateLoader
import ua.kpi.rgr.certificate.ServerCertificatePayload
import ua.kpi.rgr.common.NetworkConfig
import ua.kpi.rgr.crypto.CryptoRandom
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
        CertificateLoader.requireFile(CertificateConfig.OUTPUT_DIRECTORY.resolve(CertificateConfig.SERVER_CERTIFICATE_FILE))
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
                val serverCertificate = CertificateLoader.loadServer()
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
            }
        }
        println("[SERVER] Connection closed. Server stopped.")
    } catch (error: IOException) {
        System.err.println("[SERVER] Network or protocol error: ${error.message}")
    }
}
