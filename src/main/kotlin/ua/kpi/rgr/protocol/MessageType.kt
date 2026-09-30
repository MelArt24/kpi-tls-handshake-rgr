package ua.kpi.rgr.protocol

import kotlinx.serialization.Serializable

@Serializable
enum class MessageType {
    TEST_REQUEST,
    TEST_RESPONSE,
}
