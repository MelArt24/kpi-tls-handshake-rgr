package ua.kpi.rgr.topology

fun main() {
    println("========== DOUBLE STAR TOPOLOGY ==========\n")
    println("Nodes:")
    for (node in NodeId.entries) {
        val config = NodeDirectory.config(node)
        println("${node.name.padEnd(8)}${config.host}:${config.port}")
    }
    println("\nPhysical links:")
    for (link in DoubleStarTopology.links) println("${link.first} <-> ${link.second}")
    for ((source, destination) in listOf(NodeId.A1 to NodeId.B2, NodeId.B1 to NodeId.A2, NodeId.A1 to NodeId.A2)) {
        val route = DoubleStarTopology.findRoute(source, destination)
        println("\nRoute $source -> $destination:")
        println(route)
        println("Hops: ${route.hopCount}")
    }
    println("\nRouting decisions only; no sockets or packet forwarding.")
}
