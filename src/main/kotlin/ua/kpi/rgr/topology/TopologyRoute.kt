package ua.kpi.rgr.topology

import java.util.Collections

class TopologyRoute(nodes: List<NodeId>) {
    val nodes: List<NodeId> = Collections.unmodifiableList(nodes.toList())
    val source: NodeId get() = this.nodes.first()
    val destination: NodeId get() = this.nodes.last()
    val hopCount: Int get() = this.nodes.size - 1

    init {
        require(this.nodes.isNotEmpty()) { "A topology route must contain at least one node." }
        require(this.nodes.distinct().size == this.nodes.size) { "A topology route must not repeat nodes." }
    }

    fun nextHopAfter(node: NodeId): NodeId? {
        val index = nodes.indexOf(node)
        require(index >= 0) { "Node $node is not part of this route." }
        return nodes.getOrNull(index + 1)
    }

    override fun toString(): String = nodes.joinToString(" -> ")
}
