package ua.kpi.rgr.client

import ua.kpi.rgr.common.NetworkConfig
import ua.kpi.rgr.protocol.MessageTransport
import ua.kpi.rgr.protocol.MessageType
import ua.kpi.rgr.protocol.ProtocolMessage
import java.io.IOException
import java.net.ConnectException
import java.net.Socket

fun main() {
    println("[CLIENT] Connecting to ${NetworkConfig.HOST}:${NetworkConfig.PORT}...")
    try {
        Socket(NetworkConfig.HOST, NetworkConfig.PORT).use { socket ->
            println("[CLIENT] Connected.")
            val transport = MessageTransport(socket.getInputStream(), socket.getOutputStream())
            val request = ProtocolMessage(MessageType.TEST_REQUEST, mapOf("message" to "Hello from client"))
            println("[CLIENT] Sending protocol message:")
            println("[CLIENT] Type: ${request.type}")
            println("[CLIENT] Message: ${request.payload.getValue("message")}")
            transport.send(request)

            val response = transport.receive()
            if (response.type != MessageType.TEST_RESPONSE) {
                throw IOException("Expected TEST_RESPONSE, received ${response.type}.")
            }
            val message = response.payload["message"]
                ?: throw IOException("TEST_RESPONSE is missing the 'message' payload field.")
            println("[CLIENT] Received protocol message:")
            println("[CLIENT] Type: ${response.type}")
            println("[CLIENT] Message: $message")
        }
        println("[CLIENT] Connection closed.")
    } catch (error: ConnectException) {
        System.err.println("[CLIENT] Could not connect. Start ServerMain first. Details: ${error.message}")
    } catch (error: IOException) {
        System.err.println("[CLIENT] Network or protocol error: ${error.message}")
    }
}
