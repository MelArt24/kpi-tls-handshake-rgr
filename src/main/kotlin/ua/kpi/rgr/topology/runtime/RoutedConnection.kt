package ua.kpi.rgr.topology.runtime

import ua.kpi.rgr.topology.NodeId
import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket

class RoutedConnection internal constructor(
    val source: NodeId,
    val destination: NodeId,
    val routeId: String,
    private val socket: Socket,
    private val onClose: () -> Unit,
) : Closeable {
    val inputStream: InputStream get() = socket.getInputStream()
    val outputStream: OutputStream get() = socket.getOutputStream()

    override fun close() {
        try { socket.close() } finally { onClose() }
    }
}
