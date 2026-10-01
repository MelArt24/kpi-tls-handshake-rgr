package ua.kpi.rgr.crypto

import java.io.IOException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AesGcmTest {
    private val key = ByteArray(32) { it.toByte() }
    private val aad = "CLIENT_FINISHED".toByteArray(Charsets.UTF_8)
    private val plaintext = "CLIENT_READY".toByteArray(Charsets.UTF_8)

    @Test
    fun `AES256 round trip includes 128 bit tag and 12 byte IV`() {
        val encrypted = AesGcm.encrypt(plaintext, key, aad)
        assertEquals(12, encrypted.iv.size)
        assertEquals(plaintext.size + 16, encrypted.ciphertext.size)
        assertContentEquals(plaintext, AesGcm.decrypt(encrypted, key, aad))
    }

    @Test
    fun `UTF8 plaintext survives encryption`() {
        val text = "Привіт, client!\nSecond line".toByteArray(Charsets.UTF_8)
        assertContentEquals(text, AesGcm.decrypt(AesGcm.encrypt(text, key, aad), key, aad))
    }

    @Test
    fun `each encryption generates a fresh IV`() {
        assertFalse(AesGcm.encrypt(plaintext, key, aad).iv.contentEquals(AesGcm.encrypt(plaintext, key, aad).iv))
    }

    @Test
    fun `wrong key fails authentication`() {
        val encrypted = AesGcm.encrypt(plaintext, key, aad)
        assertAuthenticationFailure { AesGcm.decrypt(encrypted, changed(key), aad) }
    }

    @Test
    fun `modified ciphertext fails authentication`() {
        val encrypted = AesGcm.encrypt(plaintext, key, aad)
        assertAuthenticationFailure { AesGcm.decrypt(encrypted.copy(ciphertext = changed(encrypted.ciphertext)), key, aad) }
    }

    @Test
    fun `modified final tag byte fails authentication`() {
        val encrypted = AesGcm.encrypt(plaintext, key, aad)
        val modified = changed(encrypted.ciphertext, encrypted.ciphertext.lastIndex)
        assertAuthenticationFailure { AesGcm.decrypt(encrypted.copy(ciphertext = modified), key, aad) }
    }

    @Test
    fun `modified IV fails authentication`() {
        val encrypted = AesGcm.encrypt(plaintext, key, aad)
        assertAuthenticationFailure { AesGcm.decrypt(encrypted.copy(iv = changed(encrypted.iv)), key, aad) }
    }

    @Test
    fun `different message type AAD fails authentication`() {
        val encrypted = AesGcm.encrypt(plaintext, key, aad)
        assertAuthenticationFailure { AesGcm.decrypt(encrypted, key, "SERVER_FINISHED".toByteArray(Charsets.UTF_8)) }
    }

    @Test
    fun `invalid key lengths are rejected in both operations`() {
        val encrypted = AesGcm.encrypt(plaintext, key, aad)
        for (size in listOf(0, 16, 24, 31, 33)) {
            assertFailsWith<IOException> { AesGcm.encrypt(plaintext, ByteArray(size), aad) }
            assertFailsWith<IOException> { AesGcm.decrypt(encrypted, ByteArray(size), aad) }
        }
    }

    @Test
    fun `invalid IV lengths and missing tag are rejected`() {
        val encrypted = AesGcm.encrypt(plaintext, key, aad)
        for (size in listOf(0, 11, 13)) {
            assertFailsWith<IOException> { AesGcm.decrypt(encrypted.copy(iv = ByteArray(size)), key, aad) }
        }
        assertFailsWith<IOException> { AesGcm.decrypt(encrypted.copy(ciphertext = ByteArray(15)), key, aad) }
    }

    private fun changed(bytes: ByteArray, index: Int = 0) = bytes.copyOf().also { it[index] = (it[index].toInt() xor 1).toByte() }

    private fun assertAuthenticationFailure(operation: () -> ByteArray) {
        val error = assertFailsWith<IOException> { operation() }
        assertTrue(error.message.orEmpty().contains("authentication failed"))
    }
}
