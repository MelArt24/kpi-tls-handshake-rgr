package ua.kpi.rgr.topology

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class NodeDirectoryTest {
    @Test
    fun `six canonical configs separate socket location from certificate identity`() {
        assertEquals(listOf(9001, 9002, 9003, 9004, 9005, 9006), NodeDirectory.configs.map { it.port })
        assertEquals(listOf("a1.rgr.local", "a2.rgr.local", "hub-a.rgr.local", "hub-b.rgr.local", "b1.rgr.local", "b2.rgr.local"),
            NodeDirectory.configs.map { it.certificateIdentity })
        for (id in NodeId.entries) {
            assertEquals(id, NodeDirectory.config(id).id)
            assertEquals("localhost", NodeDirectory.config(id).host)
        }
    }

    @Test
    fun `invalid node directories are rejected`() {
        val configs = NodeDirectory.configs
        assertFailsWith<IllegalArgumentException> { NodeDirectory.validate(configs.dropLast(1)) }
        assertFailsWith<IllegalArgumentException> { NodeDirectory.validate(configs + configs.first()) }
        assertFailsWith<IllegalArgumentException> { NodeDirectory.validate(configs.dropLast(1) + configs.first()) }
        for (invalid in listOf(
            configs.first().copy(port = configs[1].port),
            configs.first().copy(port = 0),
            configs.first().copy(port = 65536),
            configs.first().copy(host = " "),
            configs.first().copy(certificateIdentity = " "),
            configs.first().copy(certificateIdentity = configs[1].certificateIdentity),
            configs.first().copy(certificateIdentity = "localhost"),
        )) {
            assertFailsWith<IllegalArgumentException> { NodeDirectory.validate(listOf(invalid) + configs.drop(1)) }
        }
    }
}
