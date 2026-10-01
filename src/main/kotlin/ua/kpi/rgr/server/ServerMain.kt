package ua.kpi.rgr.server

import ua.kpi.rgr.handshake.HandshakeResponder
import ua.kpi.rgr.certificate.ServerCredentialsLoader
import ua.kpi.rgr.common.NetworkConfig
import ua.kpi.rgr.crypto.SecureApplicationData
import ua.kpi.rgr.protocol.MessageTransport
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket

fun main() {
    try {
        val credentials = ServerCredentialsLoader.load()
        ServerSocket(NetworkConfig.PORT, 1, InetAddress.getByName(NetworkConfig.HOST)).use { server ->
            println("[SERVER] Started on ${NetworkConfig.HOST}:${NetworkConfig.PORT}.")
            println("[SERVER] Waiting for client...")
            server.accept().use { client ->
                println("[SERVER] Client connected: ${client.remoteSocketAddress}")
                val transport = MessageTransport(client.getInputStream(), client.getOutputStream(), ::println)
                val session = HandshakeResponder(::println).establish(transport, credentials)

                val console = System.`in`.bufferedReader(Charsets.UTF_8)
                println("[SERVER] Secure chat started. Reply after each client message; type /exit to close.")
                while (true) {
                    val text = session.receiveText()
                    if (text == SecureApplicationData.EXIT_COMMAND) {
                        println("[SERVER] Client ended the chat.")
                        break
                    }
                    println("[SERVER] Client: $text")
                    print("[SERVER] You: ")
                    System.out.flush()
                    val reply = console.readLine() ?: SecureApplicationData.EXIT_COMMAND
                    session.sendText(reply)
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
