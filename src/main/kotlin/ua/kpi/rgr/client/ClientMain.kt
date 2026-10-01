package ua.kpi.rgr.client

import ua.kpi.rgr.handshake.HandshakeInitiator
import ua.kpi.rgr.certificate.CertificateLoader
import ua.kpi.rgr.common.NetworkConfig
import ua.kpi.rgr.crypto.SecureApplicationData
import ua.kpi.rgr.protocol.MessageTransport
import java.io.IOException
import java.net.ConnectException
import java.net.Socket

fun main() {
    println("[CLIENT] Connecting to ${NetworkConfig.HOST}:${NetworkConfig.PORT}...")
    try {
        val trustedRoot = CertificateLoader.loadRoot()
        Socket(NetworkConfig.HOST, NetworkConfig.PORT).use { socket ->
            println("[CLIENT] Connected.")
            val transport = MessageTransport(socket.getInputStream(), socket.getOutputStream(), ::println)
            val session = HandshakeInitiator(::println).establish(transport, trustedRoot, NetworkConfig.HOST)

            val console = System.`in`.bufferedReader(Charsets.UTF_8)
            println("[CLIENT] Secure chat started. Type /exit to close; take turns with the server.")
            while (true) {
                print("[CLIENT] You: ")
                System.out.flush()
                val text = console.readLine() ?: SecureApplicationData.EXIT_COMMAND
                session.sendText(text)
                println("[CLIENT] Sent encrypted APPLICATION_DATA.")
                if (text == SecureApplicationData.EXIT_COMMAND) break

                val reply = session.receiveText()
                if (reply == SecureApplicationData.EXIT_COMMAND) {
                    println("[CLIENT] Server ended the chat.")
                    break
                }
                println("[CLIENT] Server: $reply")
            }
            println("[CLIENT] Secure chat closed.")
        }
        println("[CLIENT] Connection closed.")
    } catch (error: ConnectException) {
        System.err.println("[CLIENT] Could not connect. Start ServerMain first. Details: ${error.message}")
    } catch (error: IOException) {
        System.err.println("[CLIENT] Network or protocol error: ${error.message}")
    }
}
