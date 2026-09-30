package ua.kpi.rgr.client

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
            println("[CLIENT] Hello exchange completed.")
        }
        println("[CLIENT] Connection closed.")
    } catch (error: ConnectException) {
        System.err.println("[CLIENT] Could not connect. Start ServerMain first. Details: ${error.message}")
    } catch (error: IOException) {
        System.err.println("[CLIENT] Network or protocol error: ${error.message}")
    }
}
