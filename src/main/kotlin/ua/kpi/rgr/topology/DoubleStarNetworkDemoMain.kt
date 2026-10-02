package ua.kpi.rgr.topology

import ua.kpi.rgr.certificate.NodeCredentialsLoader
import ua.kpi.rgr.handshake.HandshakeInitiator
import ua.kpi.rgr.handshake.HandshakeResponder
import ua.kpi.rgr.protocol.MessageTransport
import ua.kpi.rgr.topology.runtime.TopologyNodeRuntime
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

fun main() {
    val source = NodeId.A1
    val destination = NodeId.B2

    val root = NodeCredentialsLoader.loadRoot()
    val credentials = NodeId.entries.associateWith { NodeCredentialsLoader.load(it) }
    val completed = CompletableFuture<Unit>()

    val runtimes = NodeId.entries.associateWith {
        TopologyNodeRuntime(it, logger = ::println)
    }

    try {
        for ((id, runtime) in runtimes) {
            runtime.start { connection ->
                try {
                    check(id == destination) {
                        "Unexpected endpoint $id for demo route $source -> $destination."
                    }
                    check(connection.source == source)
                    check(connection.destination == destination)

                    val logger: (String) -> Unit = {
                        println("[$id][ENDPOINT] $it")
                    }

                    val session = HandshakeResponder(logger).establish(
                        MessageTransport(
                            connection.inputStream,
                            connection.outputStream,
                            logger,
                        ),
                        credentials.getValue(id),
                    )

                    val greeting = session.receiveText()
                    println("[$id] Received after decryption: $greeting")

                    session.sendText("Вітаю, $source!")

                    val longText = session.receiveText()
                    check(longText == LONG_DEMO_TEXT)

                    println(
                        "[$id] Long Ukrainian message authenticated: " +
                                "${longText.toByteArray(Charsets.UTF_8).size} bytes",
                    )

                    session.sendText("Довге повідомлення отримано")

                    check(session.receiveText() == "/exit")

                    completed.complete(Unit)
                } catch (error: Exception) {
                    completed.completeExceptionally(error)
                    throw error
                }
            }
        }

        println()
        println("========== DOUBLE STAR DEMO ==========")
        println("Source: $source")
        println("Destination: $destination")
        println("Route: ${DoubleStarTopology.findRoute(source, destination)}")
        println()

        runtimes.getValue(source).connect(destination).use { connection ->
            val logger: (String) -> Unit = {
                println("[$source][ENDPOINT] $it")
            }

            val session = HandshakeInitiator(logger).establish(
                MessageTransport(
                    connection.inputStream,
                    connection.outputStream,
                    logger,
                ),
                root,
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
    } finally {
        runtimes.values
            .toList()
            .asReversed()
            .forEach { it.close() }
    }

    println(
        "Double Star demonstration completed: " +
                "$source -> $destination; all six runtimes stopped.",
    )
}

private val LONG_DEMO_TEXT =
    "Довге українське повідомлення через два хаби!\n".repeat(30)
