package ua.kpi.rgr.server

import ua.kpi.rgr.common.NetworkConfig
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
                client.getInputStream().bufferedReader(Charsets.UTF_8).use { reader ->
                    client.getOutputStream().bufferedWriter(Charsets.UTF_8).use { writer ->
                        val message = reader.readLine()
                            ?: throw IOException("Client closed the connection before sending a message.")
                        println("[SERVER] Received: $message")
                        writer.write("Hello from server")
                        writer.newLine()
                        writer.flush()
                        println("[SERVER] Response sent.")
                    }
                }
            }
        }
        println("[SERVER] Connection closed. Server stopped.")
    } catch (error: IOException) {
        System.err.println("[SERVER] Network error: ${error.message}")
    }
}
