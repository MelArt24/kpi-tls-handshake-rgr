package ua.kpi.rgr.crypto

import ua.kpi.rgr.protocol.ApplicationDataPayload
import ua.kpi.rgr.protocol.ProtocolMessage
import java.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class SecureApplicationDataTest {
    private val keys = SessionKeys(ByteArray(32) { it.toByte() }, ByteArray(32) { (it + 32).toByte() })

    @Test
    fun `UTF8 Ukrainian and ordinary text survive both directions exactly`() {
        for (text in listOf("Hello server!", "Привіт! Як справи?", "Привіт, клієнте! 👋")) {
            assertEquals(text, SecureApplicationData.decryptClientToServer(SecureApplicationData.encryptClientToServer(text, keys), keys))
            assertEquals(text, SecureApplicationData.decryptServerToClient(SecureApplicationData.encryptServerToClient(text, keys), keys))
        }
    }

    @Test
    fun `long multiline and empty text survive exactly`() {
        for (text in listOf("Рядок з пробілами\r\nNext line\n".repeat(1000), "")) {
            assertEquals(text, SecureApplicationData.decryptClientToServer(SecureApplicationData.encryptClientToServer(text, keys), keys))
            assertEquals(text, SecureApplicationData.decryptServerToClient(SecureApplicationData.encryptServerToClient(text, keys), keys))
        }
    }

    @Test
    fun `multiple messages have independent IVs`() {
        val ivs = (1..5).map {
            ApplicationDataPayload.decode(SecureApplicationData.encryptClientToServer("Same text", keys)).iv.toList()
        }
        assertEquals(5, ivs.toSet().size)
    }

    @Test
    fun `wrong directional key fails`() {
        val message = SecureApplicationData.encryptClientToServer("Hello", keys)
        val wrong = SessionKeys(keys.serverWriteKey, keys.clientWriteKey)
        assertFailsWith<IOException> { SecureApplicationData.decryptClientToServer(message, wrong) }
        val reply = SecureApplicationData.encryptServerToClient("Reply", keys)
        assertFailsWith<IOException> { SecureApplicationData.decryptServerToClient(reply, wrong) }
    }

    @Test
    fun `opposite direction AAD fails even when the same key is supplied`() {
        val sameKey = SessionKeys(keys.clientWriteKey, keys.clientWriteKey)
        val request = SecureApplicationData.encryptClientToServer("Hello", sameKey)
        assertFailsWith<IOException> { SecureApplicationData.decryptServerToClient(request, sameKey) }
        val reply = SecureApplicationData.encryptServerToClient("Reply", sameKey)
        assertFailsWith<IOException> { SecureApplicationData.decryptClientToServer(reply, sameKey) }
    }

    @Test
    fun `modified ciphertext and final tag fail authentication`() {
        val message = SecureApplicationData.encryptClientToServer("Hello server", keys)
        val encrypted = ApplicationDataPayload.decode(message)
        for (index in listOf(0, encrypted.ciphertext.lastIndex)) {
            val changed = encrypted.ciphertext.copyOf().also { it[index] = (it[index].toInt() xor 1).toByte() }
            assertFailsWith<IOException> {
                SecureApplicationData.decryptClientToServer(ApplicationDataPayload.encode(encrypted.copy(ciphertext = changed)), keys)
            }
        }
    }

    @Test
    fun `modified IV fails authentication`() {
        val message = SecureApplicationData.encryptServerToClient("Hello client", keys)
        val encrypted = ApplicationDataPayload.decode(message)
        val changed = encrypted.iv.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFailsWith<IOException> {
            SecureApplicationData.decryptServerToClient(ApplicationDataPayload.encode(encrypted.copy(iv = changed)), keys)
        }
    }

    @Test
    fun `exit command is encrypted in either direction`() {
        val request = SecureApplicationData.encryptClientToServer("/exit", keys)
        val reply = SecureApplicationData.encryptServerToClient("/exit", keys)
        assertEquals("/exit", SecureApplicationData.decryptClientToServer(request, keys))
        assertEquals("/exit", SecureApplicationData.decryptServerToClient(reply, keys))
        assertFalse(request.payload.values.any { it == "/exit" })
        assertFalse(reply.payload.values.any { it == "/exit" })
    }

    @Test
    fun `handshake derived keys support repeated request reply without rederivation`() {
        val premaster = ByteArray(48) { it.toByte() }
        val clientRandom = ByteArray(32) { (it + 48).toByte() }
        val serverRandom = ByteArray(32) { (it + 80).toByte() }
        val clientKeys = SessionKeyDerivation.derive(premaster, clientRandom, serverRandom)
        val serverKeys = SessionKeyDerivation.derive(premaster.copyOf(), clientRandom.copyOf(), serverRandom.copyOf())
        for (index in 1..3) {
            val request = SecureApplicationData.encryptClientToServer("Привіт $index", clientKeys)
            assertEquals("Привіт $index", SecureApplicationData.decryptClientToServer(request, serverKeys))
            val reply = SecureApplicationData.encryptServerToClient("Відповідь $index", serverKeys)
            assertEquals("Відповідь $index", SecureApplicationData.decryptServerToClient(reply, clientKeys))
        }
    }
}
