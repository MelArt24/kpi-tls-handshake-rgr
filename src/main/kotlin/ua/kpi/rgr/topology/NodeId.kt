package ua.kpi.rgr.topology

import kotlinx.serialization.Serializable

@Serializable
enum class NodeId(val certificateIdentity: String, val directoryName: String) {
    A1("a1.rgr.local", "a1"),
    A2("a2.rgr.local", "a2"),
    HUB_A("hub-a.rgr.local", "hub-a"),
    HUB_B("hub-b.rgr.local", "hub-b"),
    B1("b1.rgr.local", "b1"),
    B2("b2.rgr.local", "b2"),
}
