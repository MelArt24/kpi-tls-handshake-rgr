package ua.kpi.rgr.certificate

import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPublicKey
import javax.security.auth.x500.X500Principal
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CertificateGeneratorTest {
    @TempDir
    lateinit var directory: Path

    @Test
    fun `Root CA is self-signed and currently valid`() {
        val root = material.rootCertificate
        root.checkValidity()
        root.verify(root.publicKey)
        assertEquals(root.subjectX500Principal, root.issuerX500Principal)
        assertEquals(X500Principal(CertificateConfig.ROOT_SUBJECT), root.subjectX500Principal)
    }

    @Test
    fun `Root CA has critical CA constraints and signing usages`() {
        val root = material.rootCertificate
        assertTrue(root.basicConstraints >= 0)
        assertTrue(root.criticalExtensionOIDs.contains("2.5.29.19"))
        assertTrue(root.keyUsage[5])
        assertTrue(root.keyUsage[6])
    }

    @Test
    fun `server certificate is signed by Root CA and currently valid`() {
        val server = material.serverCertificate
        server.checkValidity()
        server.verify(material.rootCertificate.publicKey)
        assertEquals(material.rootCertificate.subjectX500Principal, server.issuerX500Principal)
    }

    @Test
    fun `server certificate is not a CA`() {
        assertEquals(-1, material.serverCertificate.basicConstraints)
    }

    @Test
    fun `server certificate contains generated server public key`() {
        assertContentEquals(material.serverKeyPair.public.encoded, material.serverCertificate.publicKey.encoded)
    }

    @Test
    fun `server subject identifies localhost`() {
        assertEquals(X500Principal("CN=localhost"), material.serverCertificate.subjectX500Principal)
    }

    @Test
    fun `server SAN contains localhost DNS`() {
        assertTrue(material.serverCertificate.subjectAlternativeNames.any { it[0] == 2 && it[1] == "localhost" })
    }

    @Test
    fun `server SAN contains loopback IP`() {
        assertTrue(material.serverCertificate.subjectAlternativeNames.any { it[0] == 7 && it[1] == "127.0.0.1" })
    }

    @Test
    fun `server permits key encipherment digital signature and server authentication`() {
        val server = material.serverCertificate
        assertTrue(server.keyUsage[0])
        assertTrue(server.keyUsage[2])
        assertTrue(server.extendedKeyUsage.contains("1.3.6.1.5.5.7.3.1"))
    }

    @Test
    fun `certificates use independent RSA-2048 keys positive distinct serials and SHA256withRSA`() {
        val root = material.rootCertificate
        val server = material.serverCertificate
        for (certificate in listOf(root, server)) {
            assertEquals(2048, (certificate.publicKey as RSAPublicKey).modulus.bitLength())
            assertEquals("SHA256withRSA", certificate.sigAlgName)
            assertTrue(certificate.serialNumber.signum() > 0)
        }
        assertFalse(root.publicKey.encoded.contentEquals(server.publicKey.encoded))
        assertFalse(root.serialNumber == server.serialNumber)
        assertTrue(root.notAfter.after(server.notAfter))
    }

    @Test
    fun `saved PEM certificates load using JVM X509 factory`() {
        val output = directory.resolve("new-certificates")
        generator.save(material, output)
        val factory = CertificateFactory.getInstance("X.509")
        for ((file, expected) in listOf(
            CertificateConfig.ROOT_CERTIFICATE_FILE to material.rootCertificate,
            CertificateConfig.SERVER_CERTIFICATE_FILE to material.serverCertificate,
        )) {
            val path = output.resolve(file)
            val loaded = Files.newInputStream(path).use { factory.generateCertificate(it) as X509Certificate }
            assertEquals(expected, loaded)
            val lines = Files.readAllLines(path)
            assertEquals("-----BEGIN CERTIFICATE-----", lines.first())
            assertEquals("-----END CERTIFICATE-----", lines.last())
            assertTrue(lines.subList(1, lines.lastIndex).all { it.length <= 64 })
        }
    }

    @Test
    fun `PKCS12 contains only server private key and ordered certificate chain`() {
        generator.save(material, directory)
        val password = CertificateConfig.KEYSTORE_PASSWORD.toCharArray()
        val keyStore = KeyStore.getInstance("PKCS12")
        Files.newInputStream(directory.resolve(CertificateConfig.SERVER_KEYSTORE_FILE)).use { keyStore.load(it, password) }
        assertEquals(1, keyStore.size())
        assertTrue(keyStore.isKeyEntry(CertificateConfig.SERVER_ALIAS))
        assertContentEquals(material.serverKeyPair.private.encoded, keyStore.getKey(CertificateConfig.SERVER_ALIAS, password).encoded)
        val chain = keyStore.getCertificateChain(CertificateConfig.SERVER_ALIAS)
        assertEquals(2, chain.size)
        assertEquals(material.serverCertificate, chain[0])
        assertEquals(material.rootCertificate, chain[1])
        password.fill('\u0000')
        assertEquals(
            setOf(CertificateConfig.ROOT_CERTIFICATE_FILE, CertificateConfig.SERVER_CERTIFICATE_FILE, CertificateConfig.SERVER_KEYSTORE_FILE),
            Files.list(directory).use { paths -> paths.map { it.fileName.toString() }.toList().toSet() },
        )
    }

    companion object {
        private val generator = CertificateGenerator()
        private val material by lazy { generator.generate() }
    }
}
