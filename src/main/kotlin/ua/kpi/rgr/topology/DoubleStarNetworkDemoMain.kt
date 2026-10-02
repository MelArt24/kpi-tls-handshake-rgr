package ua.kpi.rgr.topology

import ua.kpi.rgr.certificate.NodeCredentialsLoader
import ua.kpi.rgr.handshake.HandshakeInitiator
import ua.kpi.rgr.handshake.HandshakeResponder
import ua.kpi.rgr.protocol.MessageTransport
import ua.kpi.rgr.topology.runtime.TopologyNodeRuntime
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

fun main() {
    val root = NodeCredentialsLoader.loadRoot()
    val credentials = NodeId.entries.associateWith { NodeCredentialsLoader.load(it) }
    val completions = ConcurrentHashMap<NodeId, CompletableFuture<Unit>>()
    val runtimes = NodeId.entries.associateWith { TopologyNodeRuntime(it, logger = ::println) }
    try {
        for ((id, runtime) in runtimes) runtime.start { connection ->
            try {
                val logger: (String) -> Unit = { println("[$id][ENDPOINT] $it") }
                val session = HandshakeResponder(logger).establish(
                    MessageTransport(connection.inputStream, connection.outputStream, logger), credentials.getValue(id),
                )
                println("[$id] Received after decryption: ${session.receiveText()}")
                session.sendText("Вітаю, ${connection.source}!")
                val longText = session.receiveText()
                check(longText == LONG_DEMO_TEXT)
                println("[$id] Long Ukrainian message authenticated: ${longText.toByteArray(Charsets.UTF_8).size} bytes")
                session.sendText("Довге повідомлення отримано")
                check(session.receiveText() == "/exit")
                completions.getValue(id).complete(Unit)
            } catch (error: Exception) {
                completions[id]?.completeExceptionally(error)
                throw error
            }
        }
        for ((source, destination) in listOf(NodeId.A1 to NodeId.B2, NodeId.B2 to NodeId.A1)) {
            val completed = CompletableFuture<Unit>()
            completions[destination] = completed
            runtimes.getValue(source).connect(destination).use { connection ->
                val logger: (String) -> Unit = { println("[$source][ENDPOINT] $it") }
                val session = HandshakeInitiator(logger).establish(
                    MessageTransport(connection.inputStream, connection.outputStream, logger), root,
                    NodeDirectory.config(destination).certificateIdentity,
                )
                session.sendText("Привіт через Double Star!")
                check(session.receiveText() == "Вітаю, $source!")
                println("[$source] Encrypted reply authenticated.")
                session.sendText(LONG_DEMO_TEXT)
                check(session.receiveText() == "Довге повідомлення отримано")
                session.sendText("/exit")
                completed.get(30, TimeUnit.SECONDS)
            }
        }
    } finally {
        runtimes.values.toList().asReversed().forEach { it.close() }
    }
    println("Double Star demonstration completed; all six runtimes stopped.")
}

private val LONG_DEMO_TEXT = "Довге українське повідомлення через два хаби!\n".repeat(30)
