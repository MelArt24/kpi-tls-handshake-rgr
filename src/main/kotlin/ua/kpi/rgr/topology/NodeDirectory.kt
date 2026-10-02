package ua.kpi.rgr.topology

import ua.kpi.rgr.common.NetworkConfig

data class NodeConfig(
    val id: NodeId,
    val host: String,
    val port: Int,
    val certificateIdentity: String,
)

object NodeDirectory {
    val configs: List<NodeConfig> = NodeId.entries.mapIndexed { index, id ->
        NodeConfig(id, NetworkConfig.HOST, 9001 + index, id.certificateIdentity)
    }.also(::validate)

    fun config(id: NodeId): NodeConfig = configs.single { it.id == id }

    fun validate(configs: List<NodeConfig>) {
        require(configs.size == NodeId.entries.size && configs.map { it.id }.toSet() == NodeId.entries.toSet()) {
            "Exactly one configuration for each of the six NodeIds is required."
        }
        require(configs.map { it.port }.toSet().size == configs.size) { "Node ports must be unique." }
        require(configs.map { it.certificateIdentity }.toSet().size == configs.size) { "Certificate identities must be unique." }
        for (config in configs) {
            require(config.port in 1..65535) { "Invalid port for ${config.id}." }
            require(config.host.isNotBlank()) { "Host must not be blank for ${config.id}." }
            require(config.certificateIdentity.isNotBlank()) { "Certificate identity must not be blank for ${config.id}." }
            require(config.certificateIdentity == config.id.certificateIdentity) { "Certificate identity must be canonical for ${config.id}." }
        }
    }
}
