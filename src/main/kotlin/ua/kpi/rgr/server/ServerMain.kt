package ua.kpi.rgr.server

import ua.kpi.rgr.common.NetworkConfig
import ua.kpi.rgr.protocol.MessageTransport
import ua.kpi.rgr.protocol.MessageType
import ua.kpi.rgr.protocol.ProtocolMessage
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket

fun main() {
    try {
        ServerSocket(NetworkConfig.PORT, 1, InetAddress.getByName(NetworkConfig.HOST)).use { server ->
            println("[SERVER] Started on ${NetworkConfig.HOST}:${NetworkConfig.PORT}.")
            println("[SERVER] Waiting for client...")
            server.accept().use { client ->
                println("[SERVER] Client connected: ${client.remoteSocketAddress}")
                val transport = MessageTransport(client.getInputStream(), client.getOutputStream())
                val request = transport.receive()
                if (request.type != MessageType.TEST_REQUEST) {
                    throw IOException("Expected TEST_REQUEST, received ${request.type}.")
                }
                val message = request.payload["message"]
                    ?: throw IOException("TEST_REQUEST is missing the 'message' payload field.")
                println("[SERVER] Received protocol message:")
                println("[SERVER] Type: ${request.type}")
                println("[SERVER] Message: $message")

                val response = ProtocolMessage(MessageType.TEST_RESPONSE, mapOf("message" to "Hello from server"))
                println("[SERVER] Sending protocol message:")
                println("[SERVER] Type: ${response.type}")
                println("[SERVER] Message: ${response.payload.getValue("message")}")
                transport.send(response)
            }
        }
        println("[SERVER] Connection closed. Server stopped.")
    } catch (error: IOException) {
        System.err.println("[SERVER] Network or protocol error: ${error.message}")
    }
}
