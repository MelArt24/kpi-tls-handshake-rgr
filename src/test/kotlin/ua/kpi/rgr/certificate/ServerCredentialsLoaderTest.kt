package ua.kpi.rgr.certificate

import org.junit.jupiter.api.io.TempDir
import ua.kpi.rgr.crypto.PremasterSecret
import ua.kpi.rgr.crypto.CryptoFingerprint
import ua.kpi.rgr.crypto.RsaKeyExchange
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyStore
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ServerCredentialsLoaderTest {
    @TempDir
    lateinit var directory: Path

    @Test
    fun `loads RSA private key entry with matching leaf and full chain`() {
        generator.save(materialA, directory)
        val credentials = ServerCredentialsLoader.load(directory)
        assertEquals("RSA", credentials.privateKey.algorithm)
        assertContentEquals(materialA.serverKeyPair.private.encoded, credentials.privateKey.encoded)
        assertEquals(CertificateLoader.loadServer(directory), credentials.certificate)
        assertEquals(listOf(materialA.serverCertificate, materialA.rootCertificate), credentials.certificateChain)
        val password = CertificateConfig.KEYSTORE_PASSWORD.toCharArray()
        val store = KeyStore.getInstance("PKCS12")
        Files.newInputStream(directory.resolve(CertificateConfig.SERVER_KEYSTORE_FILE)).use { store.load(it, password) }
        assertTrue(store.entryInstanceOf(CertificateConfig.SERVER_ALIAS, KeyStore.PrivateKeyEntry::class.java))
        password.fill('\u0000')
    }

    @Test
    fun `authenticated certificate encrypts for corresponding loaded private key`() {
        generator.save(materialA, directory)
        val credentials = ServerCredentialsLoader.load(directory)
        val server = CertificateLoader.loadServer(directory)
        ServerCertificateValidator.validate(server, CertificateLoader.loadRoot(directory), "localhost")
        val premaster = PremasterSecret.generate()
        val encrypted = RsaKeyExchange.encryptPremaster(premaster, server.publicKey)
        val decrypted = RsaKeyExchange.decryptPremaster(encrypted, credentials.privateKey)
        assertContentEquals(premaster, decrypted)
        assertEquals(CryptoFingerprint.sha256Hex(premaster), CryptoFingerprint.sha256Hex(decrypted))
    }

    @Test
    fun `missing keystore reports generation command`() {
        generator.save(materialA, directory)
        Files.delete(directory.resolve(CertificateConfig.SERVER_KEYSTORE_FILE))
        val error = assertFailsWith<IOException> { ServerCredentialsLoader.load(directory) }
        assertTrue(error.message.orEmpty().contains("./gradlew.bat generateCertificates"))
    }

    @Test
    fun `certificate from A and keystore from B are rejected`() {
        generator.save(materialA, directory)
        val otherDirectory = directory.resolve("other")
        generator.save(materialB, otherDirectory)
        Files.copy(
            otherDirectory.resolve(CertificateConfig.SERVER_KEYSTORE_FILE),
            directory.resolve(CertificateConfig.SERVER_KEYSTORE_FILE),
            java.nio.file.StandardCopyOption.REPLACE_EXISTING,
        )
        val error = assertFailsWith<IOException> { ServerCredentialsLoader.load(directory) }
        assertTrue(error.message.orEmpty().contains("do not belong to the same generated credential set"))
    }

    @Test
    fun `missing alias and certificate-only alias are rejected`() {
        generator.save(materialA, directory)
        for (certificateOnly in listOf(false, true)) {
            val store = KeyStore.getInstance("PKCS12")
            store.load(null, null)
            if (certificateOnly) store.setCertificateEntry(CertificateConfig.SERVER_ALIAS, materialA.serverCertificate)
            writeStore(store)
            val error = assertFailsWith<IOException> { ServerCredentialsLoader.load(directory) }
            assertTrue(error.message.orEmpty().contains("private-key entry"))
        }
    }

    @Test
    fun `unrelated private key with matching leaf certificate is rejected`() {
        generator.save(materialA, directory)
        val store = KeyStore.getInstance("PKCS12")
        store.load(null, null)
        store.setKeyEntry(
            CertificateConfig.SERVER_ALIAS, materialB.serverKeyPair.private,
            CertificateConfig.KEYSTORE_PASSWORD.toCharArray(), arrayOf(materialA.serverCertificate, materialA.rootCertificate),
        )
        writeStore(store)
        assertFailsWith<IOException> { ServerCredentialsLoader.load(directory) }
    }

    private fun writeStore(store: KeyStore) {
        val password = CertificateConfig.KEYSTORE_PASSWORD.toCharArray()
        Files.newOutputStream(directory.resolve(CertificateConfig.SERVER_KEYSTORE_FILE)).use { store.store(it, password) }
        password.fill('\u0000')
    }

    companion object {
        private val generator = CertificateGenerator()
        private val materialA by lazy { generator.generate() }
        private val materialB by lazy { generator.generate() }
    }
}
