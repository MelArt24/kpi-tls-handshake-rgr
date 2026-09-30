package ua.kpi.rgr.client

import ua.kpi.rgr.certificate.CertificateConfig
import ua.kpi.rgr.certificate.CertificateLoader
import ua.kpi.rgr.certificate.ServerCertificatePayload
import ua.kpi.rgr.certificate.ServerCertificateValidator
import ua.kpi.rgr.common.NetworkConfig
import ua.kpi.rgr.crypto.CryptoRandom
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
        }
        println("[CLIENT] Connection closed.")
    } catch (error: ConnectException) {
        System.err.println("[CLIENT] Could not connect. Start ServerMain first. Details: ${error.message}")
    } catch (error: IOException) {
        System.err.println("[CLIENT] Network or protocol error: ${error.message}")
    }
}
