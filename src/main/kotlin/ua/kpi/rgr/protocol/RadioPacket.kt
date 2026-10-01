package ua.kpi.rgr.protocol

import kotlinx.serialization.Serializable

@Serializable
data class RadioPacket(
    val messageId: String,
    val fragmentIndex: Int,
    val fragmentCount: Int,
    val payload: String,
)
