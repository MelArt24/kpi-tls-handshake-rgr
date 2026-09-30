package ua.kpi.rgr.protocol

import kotlinx.serialization.Serializable

@Serializable
data class ProtocolMessage(
    val type: MessageType,
    val payload: Map<String, String> = emptyMap(),
)
