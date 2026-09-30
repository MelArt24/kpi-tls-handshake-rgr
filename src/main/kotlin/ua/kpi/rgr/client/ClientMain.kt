package ua.kpi.rgr.client

import ua.kpi.rgr.common.NetworkConfig
import java.io.IOException
import java.net.ConnectException
import java.net.Socket

fun main() {
    println("[CLIENT] Connecting to ${NetworkConfig.HOST}:${NetworkConfig.PORT}...")
    try {
        Socket(NetworkConfig.HOST, NetworkConfig.PORT).use { socket ->
            println("[CLIENT] Connected.")
            socket.getInputStream().bufferedReader(Charsets.UTF_8).use { reader ->
                socket.getOutputStream().bufferedWriter(Charsets.UTF_8).use { writer ->
                    val message = "Hello from client"
                    writer.write(message)
                    writer.newLine()
                    writer.flush()
                    println("[CLIENT] Sent: $message")
                    val response = reader.readLine()
                        ?: throw IOException("Server closed the connection before sending a response.")
                    println("[CLIENT] Received: $response")
                }
            }
        }
        println("[CLIENT] Connection closed.")
    } catch (error: ConnectException) {
        System.err.println("[CLIENT] Could not connect. Start ServerMain first. Details: ${error.message}")
    } catch (error: IOException) {
        System.err.println("[CLIENT] Network error: ${error.message}")
    }
}
