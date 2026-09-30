package ua.kpi.rgr.protocol

import java.io.IOException
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class HelloRandomPayloadTest {
    @Test
    fun `valid client and server random payloads are accepted`() {
        val bytes = ByteArray(32) { it.toByte() }
        val encoded = Base64.getEncoder().encodeToString(bytes)
        for ((type, field) in helloFields) {
            val message = ProtocolMessage(type, mapOf(field to encoded))
            assertContentEquals(bytes, HelloRandomPayload.decode(message, type, field))
        }
    }

    @Test
    fun `malformed Base64 is rejected`() {
        for ((type, field) in helloFields) {
            val message = ProtocolMessage(type, mapOf(field to "%%% invalid Base64"))
            val error = assertFailsWith<IOException> { HelloRandomPayload.decode(message, type, field) }
            assertTrue(error.message.orEmpty().contains("Invalid Base64 $field"))
        }
    }

    @Test
    fun `wrong random lengths are rejected`() {
        for ((type, field) in helloFields) {
            for (size in listOf(0, 31, 33)) {
                val message = ProtocolMessage(type, mapOf(field to Base64.getEncoder().encodeToString(ByteArray(size))))
                val error = assertFailsWith<IOException> { HelloRandomPayload.decode(message, type, field) }
                assertTrue(error.message.orEmpty().contains("must be exactly 32 bytes"))
            }
        }
    }

    @Test
    fun `missing random fields are rejected`() {
        for ((type, field) in helloFields) {
            val error = assertFailsWith<IOException> {
                HelloRandomPayload.decode(ProtocolMessage(type), type, field)
            }
            assertTrue(error.message.orEmpty().contains("missing the '$field'"))
        }
    }

    @Test
    fun `unexpected hello types are rejected`() {
        for ((type, field) in helloFields) {
            val wrongType = if (type == MessageType.CLIENT_HELLO) MessageType.SERVER_HELLO else MessageType.CLIENT_HELLO
            val error = assertFailsWith<IOException> {
                HelloRandomPayload.decode(ProtocolMessage(wrongType), type, field)
            }
            assertTrue(error.message.orEmpty().contains("Expected $type, received $wrongType"))
        }
    }

    private val helloFields = listOf(
        MessageType.CLIENT_HELLO to "clientRandom",
        MessageType.SERVER_HELLO to "serverRandom",
    )
}
