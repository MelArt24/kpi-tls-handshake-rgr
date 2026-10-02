package ua.kpi.rgr.topology

import java.util.Collections

data class TopologyLink(val first: NodeId, val second: NodeId)

object DoubleStarTopology {
    val links: List<TopologyLink> = Collections.unmodifiableList(listOf(
        TopologyLink(NodeId.A1, NodeId.HUB_A),
        TopologyLink(NodeId.A2, NodeId.HUB_A),
        TopologyLink(NodeId.HUB_A, NodeId.HUB_B),
        TopologyLink(NodeId.HUB_B, NodeId.B1),
        TopologyLink(NodeId.HUB_B, NodeId.B2),
    ))

    private val adjacency: Map<NodeId, Set<NodeId>> = NodeId.entries.associateWith { node ->
        Collections.unmodifiableSet(links.flatMap { link ->
            when (node) {
                link.first -> listOf(link.second)
                link.second -> listOf(link.first)
                else -> emptyList()
            }
        }.toSet())
    }

    init {
        val knownNodes = NodeDirectory.configs.map { it.id }.toSet()
        check(adjacency.size == 6 && adjacency.keys == knownNodes) { "Topology must contain all six configured nodes." }
        check(links.size == 5) { "Double Star must have exactly five undirected physical links." }
        check(links.all { it.first != it.second }) { "Topology must not contain self-links." }
        check(links.map { setOf(it.first, it.second) }.distinct().size == links.size) { "Duplicate undirected link." }
        for ((node, neighbors) in adjacency) {
            check(neighbors.all { it in knownNodes }) { "Topology references an unknown node." }
            check(neighbors.all { node in adjacency.getValue(it) }) { "Topology adjacency must be symmetric." }
        }
        val reachable = mutableSetOf(NodeId.entries.first())
        val queue = ArrayDeque(reachable)
        while (queue.isNotEmpty()) {
            for (neighbor in neighbors(queue.removeFirst())) {
                if (reachable.add(neighbor)) queue.addLast(neighbor)
            }
        }
        check(reachable == knownNodes) { "Double Star topology must be connected." }
    }

    fun neighbors(node: NodeId): Set<NodeId> = adjacency.getValue(node)

    fun areNeighbors(first: NodeId, second: NodeId): Boolean = second in neighbors(first)

    fun findRoute(source: NodeId, destination: NodeId): TopologyRoute {
        val queue = ArrayDeque<NodeId>()
        val visited = mutableSetOf(source)
        val previous = mutableMapOf<NodeId, NodeId>()
        queue.addLast(source)
        while (queue.isNotEmpty()) {
            val current = queue.removeFirst()
            if (current == destination) {
                val path = mutableListOf(current)
                while (path.last() != source) path.add(previous.getValue(path.last()))
                return TopologyRoute(path.asReversed())
            }
            for (neighbor in neighbors(current).sortedBy { it.ordinal }) {
                if (visited.add(neighbor)) {
                    previous[neighbor] = current
                    queue.addLast(neighbor)
                }
            }
        }
        error("No route from $source to $destination: Double Star topology is disconnected.")
    }
}
