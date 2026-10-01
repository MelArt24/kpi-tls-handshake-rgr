package ua.kpi.rgr.protocol

import kotlinx.serialization.Serializable

@Serializable
enum class MessageType {
    CLIENT_HELLO,
    SERVER_HELLO,
    CLIENT_KEY_EXCHANGE,
    CLIENT_FINISHED,
    SERVER_FINISHED,
}
