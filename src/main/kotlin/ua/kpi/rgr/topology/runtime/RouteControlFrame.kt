package ua.kpi.rgr.topology.runtime

import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import ua.kpi.rgr.topology.DoubleStarTopology
import ua.kpi.rgr.topology.NodeId
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.CharacterCodingException
import java.util.UUID

@Serializable
enum class RouteControlType { OPEN, READY }

@Serializable
data class RouteControlFrame(
    val type: RouteControlType,
    val routeId: String,
    val source: NodeId,
    val destination: NodeId,
    val sender: NodeId,
)

object RouteControlCodec {
    private val json = Json

    fun validate(frame: RouteControlFrame) {
        if (frame.routeId.isBlank()) throw IOException("Route ID must not be blank.")
        try { UUID.fromString(frame.routeId) } catch (error: IllegalArgumentException) {
            throw IOException("Route ID must be a UUID.", error)
        }
        if (frame.source == frame.destination) throw IOException("A routed tunnel needs distinct source and destination nodes.")
    }

    fun write(output: OutputStream, frame: RouteControlFrame) {
        validate(frame)
        BoundedFrames.write(output, (json.encodeToString(frame) + "\n").toByteArray(Charsets.UTF_8))
    }

    fun read(input: InputStream): RouteControlFrame {
        val bytes = BoundedFrames.read(input) ?: throw EOFException("Connection closed before route control frame.")
        val frame = try {
            val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
            json.decodeFromString<RouteControlFrame>(text)
        } catch (error: SerializationException) {
            throw IOException("Malformed route-control JSON.", error)
        } catch (error: CharacterCodingException) {
            throw IOException("Malformed route-control UTF-8.", error)
        }
        validate(frame)
        return frame
    }
}

data class RouteHops(val previous: NodeId, val next: NodeId?)

object RouteSetup {
    fun incoming(local: NodeId, frame: RouteControlFrame): RouteHops {
        RouteControlCodec.validate(frame)
        if (frame.type != RouteControlType.OPEN) throw IOException("Expected route OPEN.")
        val route = DoubleStarTopology.findRoute(frame.source, frame.destination).nodes
        val index = route.indexOf(local)
        if (index <= 0) throw IOException("Node $local is not an incoming hop on the canonical route.")
        val previous = route[index - 1]
        if (frame.sender != previous) throw IOException("Invalid previous hop: expected $previous, received ${frame.sender}.")
        return RouteHops(previous, route.getOrNull(index + 1))
    }

    fun ready(frame: RouteControlFrame, open: RouteControlFrame, expectedSender: NodeId) {
        RouteControlCodec.validate(frame)
        if (frame.type != RouteControlType.READY || frame.routeId != open.routeId || frame.source != open.source ||
            frame.destination != open.destination || frame.sender != expectedSender) {
            throw IOException("Inconsistent route READY metadata or downstream sender.")
        }
    }
}
