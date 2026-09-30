package ua.kpi.rgr.crypto

import java.io.IOException
import java.security.KeyPairGenerator
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class RsaKeyExchangeTest {
    @Test
    fun `corresponding RSA keys recover all 48 premaster bytes`() {
        val secret = PremasterSecret.generate()
        val encrypted = RsaKeyExchange.encryptPremaster(secret, keys.public)
        assertEquals(256, encrypted.size)
        assertContentEquals(secret, RsaKeyExchange.decryptPremaster(encrypted, keys.private))
    }

    @Test
    fun `encryption interoperates with explicit SHA256 and MGF1 SHA256 parameters`() {
        val secret = PremasterSecret.generate()
        val encrypted = RsaKeyExchange.encryptPremaster(secret, keys.public)
        val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
        cipher.init(Cipher.DECRYPT_MODE, keys.private, parameters)
        assertContentEquals(secret, cipher.doFinal(encrypted))
    }

    @Test
    fun `unrelated RSA private key cannot decrypt`() {
        val encrypted = RsaKeyExchange.encryptPremaster(PremasterSecret.generate(), keys.public)
        val error = assertFailsWith<IOException> { RsaKeyExchange.decryptPremaster(encrypted, otherKeys.private) }
        assertTrue(error.message.orEmpty().contains("decryption failed"))
    }

    @Test
    fun `corrupted ciphertext cannot decrypt`() {
        val encrypted = RsaKeyExchange.encryptPremaster(PremasterSecret.generate(), keys.public)
        encrypted[encrypted.size / 2] = (encrypted[encrypted.size / 2].toInt() xor 1).toByte()
        assertFailsWith<IOException> { RsaKeyExchange.decryptPremaster(encrypted, keys.private) }
    }

    @Test
    fun `non RSA public and private keys fail clearly`() {
        val ecKeys = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        val encryptionError = assertFailsWith<IOException> {
            RsaKeyExchange.encryptPremaster(PremasterSecret.generate(), ecKeys.public)
        }
        val decryptionError = assertFailsWith<IOException> {
            RsaKeyExchange.decryptPremaster(ByteArray(256), ecKeys.private)
        }
        assertTrue(encryptionError.message.orEmpty().contains("RSA public key"))
        assertTrue(decryptionError.message.orEmpty().contains("RSA private key"))
    }

    @Test
    fun `wrong input premaster and ciphertext lengths are rejected`() {
        for (size in listOf(0, 47, 49)) {
            assertFailsWith<IOException> { RsaKeyExchange.encryptPremaster(ByteArray(size), keys.public) }
        }
        for (size in listOf(0, 255, 257)) {
            assertFailsWith<IOException> { RsaKeyExchange.decryptPremaster(ByteArray(size), keys.private) }
        }
    }

    @Test
    fun `valid OAEP ciphertext containing wrong premaster length is rejected`() {
        val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
        cipher.init(Cipher.ENCRYPT_MODE, keys.public, parameters)
        val encrypted = cipher.doFinal(ByteArray(47))
        val error = assertFailsWith<IOException> { RsaKeyExchange.decryptPremaster(encrypted, keys.private) }
        assertTrue(error.message.orEmpty().contains("Recovered premaster secret must be exactly 48 bytes"))
    }

    @Test
    fun `wrong MGF1 parameters cannot decrypt`() {
        val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
        cipher.init(Cipher.ENCRYPT_MODE, keys.public, OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT))
        val encrypted = cipher.doFinal(PremasterSecret.generate())
        assertFailsWith<IOException> { RsaKeyExchange.decryptPremaster(encrypted, keys.private) }
    }

    companion object {
        private val keys by lazy { KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair() }
        private val otherKeys by lazy { KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair() }
        private val parameters = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT)
    }
}
