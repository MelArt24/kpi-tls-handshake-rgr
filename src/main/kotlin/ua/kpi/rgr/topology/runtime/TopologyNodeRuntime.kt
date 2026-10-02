package ua.kpi.rgr.topology.runtime

import ua.kpi.rgr.topology.DoubleStarTopology
import ua.kpi.rgr.topology.NodeDirectory
import ua.kpi.rgr.topology.NodeId
import java.io.Closeable
import java.io.IOException
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class TopologyNodeRuntime(
    val id: NodeId,
    private val address: (NodeId) -> InetSocketAddress = {
        NodeDirectory.config(it).let { config -> InetSocketAddress(config.host, config.port) }
    },
    private val logger: (String) -> Unit = {},
) : Closeable {
    private val workers = Executors.newCachedThreadPool { task -> Thread(task, "rgr-$id-worker") }
    private val sockets = ConcurrentHashMap.newKeySet<Socket>()
    private var listener: ServerSocket? = null
    @Volatile private var closed = false

    val localAddress: InetSocketAddress
        @Synchronized get() = listener?.localSocketAddress as? InetSocketAddress
            ?: error("Runtime $id has not started.")

    @Synchronized
    fun start(handler: (RoutedConnection) -> Unit) {
        check(!closed && listener == null) { "Runtime $id is closed or already started." }
        val server = ServerSocket()
        try { server.bind(address(id)) } catch (error: Exception) { server.close(); throw error }
        listener = server
        log("Listening ${server.inetAddress.hostName}:${server.localPort}")
        workers.execute {
            try {
                while (!closed) {
                    val socket = server.accept()
                    synchronized(this) {
                        if (closed) socket.close() else {
                            sockets.add(socket)
                            workers.execute { acceptRoute(socket, handler) }
                        }
                    }
                }
            } catch (error: IOException) {
                if (!closed) log("Listener error: ${error.message}")
            }
        }
    }

    fun connect(destination: NodeId): RoutedConnection {
        check(!closed && listener != null) { "Runtime $id must be started before connecting." }
        if (id == destination) throw IOException("A routed tunnel needs distinct source and destination nodes.")
        val route = DoubleStarTopology.findRoute(id, destination)
        val next = route.nodes[1]
        log("[ROUTE] Destination $destination; $route")
        val socket = openNeighbor(next)
        try {
            val open = RouteControlFrame(RouteControlType.OPEN, UUID.randomUUID().toString(), id, destination, id)
            RouteControlCodec.write(socket.getOutputStream(), open)
            RouteSetup.ready(RouteControlCodec.read(socket.getInputStream()), open, next)
            socket.soTimeout = 0
            log("[ROUTE] READY ${open.routeId}; endpoint traffic may begin")
            return connection(socket, open)
        } catch (error: Exception) {
            release(socket)
            throw error
        }
    }

    private fun acceptRoute(upstream: Socket, handler: (RoutedConnection) -> Unit) {
        try {
            upstream.soTimeout = SETUP_TIMEOUT_MILLIS
            val open = RouteControlCodec.read(upstream.getInputStream())
            val hops = RouteSetup.incoming(id, open)
            log("[ROUTE] OPEN ${open.source} -> ${open.destination}, ${open.routeId}")
            if (hops.next == null) {
                log("[ROUTE] Destination reached")
                RouteControlCodec.write(upstream.getOutputStream(), open.copy(type = RouteControlType.READY, sender = id))
                upstream.soTimeout = 0
                connection(upstream, open).use(handler)
            } else {
                val downstream = openNeighbor(hops.next)
                try {
                    log("[ROUTE] Forwarding toward ${hops.next}")
                    RouteControlCodec.write(downstream.getOutputStream(), open.copy(sender = id))
                    RouteSetup.ready(RouteControlCodec.read(downstream.getInputStream()), open, hops.next)
                    RouteControlCodec.write(upstream.getOutputStream(), open.copy(type = RouteControlType.READY, sender = id))
                    upstream.soTimeout = 0
                    downstream.soTimeout = 0
                    log("[ROUTE] READY upstream; raw forwarding active")
                    relay(upstream, downstream, hops.previous, hops.next)
                } finally { release(downstream) }
            }
        } catch (error: IOException) {
            if (!closed && !(upstream.isClosed && error is SocketException)) {
                log("[ROUTE] Connection stopped: ${error.message}")
            }
        } finally { release(upstream) }
    }

    private fun relay(upstream: Socket, downstream: Socket, previous: NodeId, next: NodeId) {
        val reverse = workers.submit {
            try {
                FrameRelay.forward(downstream.getInputStream(), upstream.getOutputStream()) {
                    log("[FORWARD] $next-side -> $previous-side frame $it bytes")
                }
            } catch (error: IOException) {
                if (!upstream.isClosed && !closed) log("[FORWARD] Stopped: ${error.message}")
            } finally { release(upstream); release(downstream) }
        }
        try {
            FrameRelay.forward(upstream.getInputStream(), downstream.getOutputStream()) {
                log("[FORWARD] $previous-side -> $next-side frame $it bytes")
            }
        } finally {
            release(upstream)
            release(downstream)
            try {
                reverse.get(5, TimeUnit.SECONDS)
            } catch (error: InterruptedException) {
                Thread.currentThread().interrupt()
                if (!closed) throw IOException("Relay interrupted.", error)
            } finally { reverse.cancel(true) }
        }
    }

    private fun openNeighbor(neighbor: NodeId): Socket {
        check(DoubleStarTopology.areNeighbors(id, neighbor)) { "$id cannot connect directly to non-neighbor $neighbor." }
        val socket = Socket()
        synchronized(this) {
            check(!closed) { "Runtime $id is closed." }
            sockets.add(socket)
        }
        try {
            socket.connect(address(neighbor), SETUP_TIMEOUT_MILLIS)
            socket.soTimeout = SETUP_TIMEOUT_MILLIS
            log("[ROUTE] Physical connection $id -> $neighbor")
            return socket
        } catch (error: Exception) { release(socket); throw error }
    }

    private fun connection(socket: Socket, frame: RouteControlFrame) =
        RoutedConnection(frame.source, frame.destination, frame.routeId, socket) { sockets.remove(socket) }

    private fun release(socket: Socket) {
        try { socket.close() } finally { sockets.remove(socket) }
    }

    private fun log(message: String) = logger("[$id] $message")

    override fun close() {
        synchronized(this) {
            if (closed) return
            closed = true
            listener?.close()
            sockets.toList().forEach(::release)
            workers.shutdownNow()
        }
        check(workers.awaitTermination(10, TimeUnit.SECONDS)) { "Runtime $id workers did not terminate." }
    }

    companion object { private const val SETUP_TIMEOUT_MILLIS = 5000 }
}
