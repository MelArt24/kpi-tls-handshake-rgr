package ua.kpi.rgr.topology

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DoubleStarTopologyTest {
    private val expectedNeighbors = mapOf(
        NodeId.A1 to setOf(NodeId.HUB_A),
        NodeId.A2 to setOf(NodeId.HUB_A),
        NodeId.HUB_A to setOf(NodeId.A1, NodeId.A2, NodeId.HUB_B),
        NodeId.HUB_B to setOf(NodeId.HUB_A, NodeId.B1, NodeId.B2),
        NodeId.B1 to setOf(NodeId.HUB_B),
        NodeId.B2 to setOf(NodeId.HUB_B),
    )

    @Test
    fun `exact neighbors and five distinct undirected links`() {
        for ((node, neighbors) in expectedNeighbors) assertEquals(neighbors, DoubleStarTopology.neighbors(node))
        val links = DoubleStarTopology.links
        assertEquals(5, links.size)
        assertEquals(setOf(
            setOf(NodeId.A1, NodeId.HUB_A), setOf(NodeId.A2, NodeId.HUB_A),
            setOf(NodeId.HUB_A, NodeId.HUB_B), setOf(NodeId.HUB_B, NodeId.B1), setOf(NodeId.HUB_B, NodeId.B2),
        ), links.map { setOf(it.first, it.second) }.toSet())
        assertTrue(links.all { it.first != it.second })
        for (first in NodeId.entries) for (second in NodeId.entries) {
            assertEquals(second in expectedNeighbors.getValue(first), DoubleStarTopology.areNeighbors(first, second))
            assertEquals(DoubleStarTopology.areNeighbors(first, second), DoubleStarTopology.areNeighbors(second, first))
        }
        assertTrue(DoubleStarTopology.areNeighbors(NodeId.A1, NodeId.HUB_A))
        assertTrue(DoubleStarTopology.areNeighbors(NodeId.HUB_A, NodeId.A1))
        assertFalse(DoubleStarTopology.areNeighbors(NodeId.A1, NodeId.B2))
        assertFalse(DoubleStarTopology.areNeighbors(NodeId.A1, NodeId.A2))
        assertFalse(DoubleStarTopology.areNeighbors(NodeId.B1, NodeId.B2))
    }

    @Test
    fun `BFS returns exact representative shortest routes`() {
        val paths = listOf(
            listOf(NodeId.A1, NodeId.HUB_A, NodeId.A2),
            listOf(NodeId.A1, NodeId.HUB_A),
            listOf(NodeId.A1, NodeId.HUB_A, NodeId.HUB_B),
            listOf(NodeId.A1, NodeId.HUB_A, NodeId.HUB_B, NodeId.B1),
            listOf(NodeId.A1, NodeId.HUB_A, NodeId.HUB_B, NodeId.B2),
            listOf(NodeId.A2, NodeId.HUB_A, NodeId.HUB_B, NodeId.B2),
            listOf(NodeId.A2, NodeId.HUB_A, NodeId.HUB_B, NodeId.B1),
            listOf(NodeId.HUB_A, NodeId.HUB_B, NodeId.B1),
            listOf(NodeId.B1, NodeId.HUB_B, NodeId.B2),
            listOf(NodeId.B2, NodeId.HUB_B, NodeId.HUB_A, NodeId.A1),
            listOf(NodeId.HUB_A, NodeId.HUB_B),
        )
        for (path in paths) {
            val route = DoubleStarTopology.findRoute(path.first(), path.last())
            assertEquals(path, route.nodes)
            assertEquals(path.size - 1, route.hopCount)
        }
    }

    @Test
    fun `all 36 pairs have valid deterministic reversible routes`() {
        for (source in NodeId.entries) for (destination in NodeId.entries) {
            val route = DoubleStarTopology.findRoute(source, destination)
            assertTrue(route.nodes.isNotEmpty())
            assertEquals(source, route.source)
            assertEquals(destination, route.destination)
            assertEquals(route.nodes.size, route.nodes.distinct().size)
            assertTrue(route.nodes.zipWithNext().all { (first, second) ->
                second in expectedNeighbors.getValue(first)
            })
            assertEquals(route.nodes, DoubleStarTopology.findRoute(source, destination).nodes)
            assertEquals(route.nodes.reversed(), DoubleStarTopology.findRoute(destination, source).nodes)
            if (source == destination) {
                assertEquals(listOf(source), route.nodes)
                assertEquals(0, route.hopCount)
            }
        }
    }

    @Test
    fun `route nodes resolve to existing directory metadata`() {
        val expectedPorts = mapOf(NodeId.A1 to 9001, NodeId.A2 to 9002, NodeId.HUB_A to 9003,
            NodeId.HUB_B to 9004, NodeId.B1 to 9005, NodeId.B2 to 9006)
        val expectedIdentities = mapOf(NodeId.A1 to "a1.rgr.local", NodeId.A2 to "a2.rgr.local",
            NodeId.HUB_A to "hub-a.rgr.local", NodeId.HUB_B to "hub-b.rgr.local",
            NodeId.B1 to "b1.rgr.local", NodeId.B2 to "b2.rgr.local")
        for (source in NodeId.entries) for (destination in NodeId.entries) {
            for (node in DoubleStarTopology.findRoute(source, destination).nodes) {
                val config = NodeDirectory.config(node)
                assertEquals(node, config.id)
                assertEquals("localhost", config.host)
                assertEquals(expectedPorts.getValue(node), config.port)
                assertEquals(expectedIdentities.getValue(node), config.certificateIdentity)
            }
        }
    }

    @Test
    fun `route formatting and next hop handle endpoints and misuse`() {
        val route = DoubleStarTopology.findRoute(NodeId.A1, NodeId.B2)
        assertEquals("A1 -> HUB_A -> HUB_B -> B2", route.toString())
        assertEquals(NodeId.HUB_A, route.nextHopAfter(NodeId.A1))
        assertEquals(NodeId.HUB_B, route.nextHopAfter(NodeId.HUB_A))
        assertEquals(NodeId.B2, route.nextHopAfter(NodeId.HUB_B))
        assertNull(route.nextHopAfter(NodeId.B2))
        assertFailsWith<IllegalArgumentException> { route.nextHopAfter(NodeId.A2) }
        assertFailsWith<IllegalArgumentException> { TopologyRoute(emptyList()) }
        assertFailsWith<IllegalArgumentException> { TopologyRoute(listOf(NodeId.A1, NodeId.A1)) }
    }

    @Test
    fun `exposed topology and route collections cannot mutate graph state`() {
        assertFailsWith<UnsupportedOperationException> {
            (DoubleStarTopology.links as MutableList).clear()
        }
        assertFailsWith<UnsupportedOperationException> {
            (DoubleStarTopology.neighbors(NodeId.A1) as MutableSet).add(NodeId.B2)
        }
        val input = mutableListOf(NodeId.A1, NodeId.HUB_A)
        val route = TopologyRoute(input)
        input.clear()
        assertEquals(listOf(NodeId.A1, NodeId.HUB_A), route.nodes)
        assertEquals(NodeId.A1, route.source)
        assertEquals(NodeId.HUB_A, route.destination)
        assertEquals(1, route.hopCount)
        assertFailsWith<UnsupportedOperationException> { (route.nodes as MutableList).clear() }
    }
}
