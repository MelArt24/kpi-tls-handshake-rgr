package ua.kpi.rgr.certificate

import org.junit.jupiter.api.io.TempDir
import ua.kpi.rgr.topology.NodeId
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import java.security.interfaces.RSAPublicKey
import javax.security.auth.x500.X500Principal
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class NodeCertificatesTest {
    @TempDir
    lateinit var directory: Path

    @Test
    fun `all six leaves share trust but have independent identities keys and serials`() {
        val root = material.rootCertificate
        assertEquals(X500Principal(CertificateConfig.ROOT_SUBJECT), root.subjectX500Principal)
        assertEquals(NodeId.entries.toSet(), material.nodes.keys)
        val leaves = material.nodes.values.map { it.serverCertificate }
        assertEquals(6, leaves.map { (it.publicKey as RSAPublicKey).modulus }.toSet().size)
        assertEquals(6, leaves.map { it.serialNumber }.toSet().size)
        for ((id, node) in material.nodes) {
            val certificate = node.serverCertificate
            ServerCertificateValidator.validate(certificate, root, id.certificateIdentity)
            assertEquals(X500Principal("CN=${id.certificateIdentity}"), certificate.subjectX500Principal)
            assertEquals(root.subjectX500Principal, certificate.issuerX500Principal)
            assertEquals(-1, certificate.basicConstraints)
            assertEquals("SHA256withRSA", certificate.sigAlgName)
            assertEquals(2048, (certificate.publicKey as RSAPublicKey).modulus.bitLength())
            assertTrue(certificate.serialNumber.signum() > 0)
            assertTrue(certificate.keyUsage[0] && certificate.keyUsage[2])
            assertTrue("1.3.6.1.5.5.7.3.1" in certificate.extendedKeyUsage)
            assertEquals(listOf(listOf(2, id.certificateIdentity)), certificate.subjectAlternativeNames.toList())
            assertEquals(node.serverKeyPair.public, certificate.publicKey)
            val other = NodeId.entries.first { it != id }
            assertFailsWith<IOException> { ServerCertificateValidator.validate(certificate, root, other.certificateIdentity) }
            assertFailsWith<IOException> { ServerCertificateValidator.validate(certificate, unrelated.rootCertificate, id.certificateIdentity) }
        }
    }

    @Test
    fun `all node private key entries load from their own paths with the shared chain`() {
        generator.saveNodes(material, directory)
        assertEquals(material.rootCertificate, NodeCredentialsLoader.loadRoot(directory))
        for (id in NodeId.entries) {
            val loaded = NodeCredentialsLoader.load(id, directory)
            assertEquals("RSA", loaded.privateKey.algorithm)
            assertEquals(material.nodes.getValue(id).serverCertificate, loaded.certificate)
            assertEquals(listOf(loaded.certificate, material.rootCertificate), loaded.certificateChain)
            val store = readStore(id)
            assertTrue(store.entryInstanceOf(NodeCertificateConfig.ALIAS, KeyStore.PrivateKeyEntry::class.java))
        }
    }

    @Test
    fun `missing node certificate and keystore give actionable errors`() {
        assertTrue(assertFailsWith<IOException> { NodeCredentialsLoader.load(NodeId.A1, directory) }
            .message!!.contains("generateNodeCertificates"))
        generator.saveNodes(material, directory)
        Files.delete(nodePath(NodeId.A1, NodeCertificateConfig.KEYSTORE_FILE))
        assertTrue(assertFailsWith<IOException> { NodeCredentialsLoader.load(NodeId.A1, directory) }
            .message!!.contains("generateNodeCertificates"))
    }

    @Test
    fun `keystore from a different node is rejected`() {
        generator.saveNodes(material, directory)
        Files.copy(nodePath(NodeId.B2, NodeCertificateConfig.KEYSTORE_FILE),
            nodePath(NodeId.A1, NodeCertificateConfig.KEYSTORE_FILE), StandardCopyOption.REPLACE_EXISTING)
        assertFailsWith<IOException> { NodeCredentialsLoader.load(NodeId.A1, directory) }
    }

    @Test
    fun `missing private key alias is rejected`() {
        generator.saveNodes(material, directory)
        val store = readStore(NodeId.A1)
        store.deleteEntry(NodeCertificateConfig.ALIAS)
        writeStore(NodeId.A1, store)
        assertFailsWith<IOException> { NodeCredentialsLoader.load(NodeId.A1, directory) }
    }

    @Test
    fun `unrelated private key paired with a matching leaf is rejected`() {
        generator.saveNodes(material, directory)
        val store = readStore(NodeId.A1)
        val password = CertificateConfig.KEYSTORE_PASSWORD.toCharArray()
        try {
            store.setKeyEntry(NodeCertificateConfig.ALIAS, unrelated.serverKeyPair.private, password,
                arrayOf(material.nodes.getValue(NodeId.A1).serverCertificate, material.rootCertificate))
            writeStore(NodeId.A1, store)
        } finally {
            password.fill('\u0000')
        }
        assertFailsWith<IOException> { NodeCredentialsLoader.load(NodeId.A1, directory) }
    }

    @Test
    fun `changed topology root and wrong node identity are rejected`() {
        generator.saveNodes(material, directory)
        generator.save(unrelated, directory)
        assertFailsWith<IOException> { NodeCredentialsLoader.load(NodeId.A1, directory) }
        generator.saveNodes(material, directory)
        for (file in listOf(NodeCertificateConfig.CERTIFICATE_FILE, NodeCertificateConfig.KEYSTORE_FILE)) {
            Files.copy(nodePath(NodeId.B2, file), nodePath(NodeId.A1, file), StandardCopyOption.REPLACE_EXISTING)
        }
        assertFailsWith<IOException> { NodeCredentialsLoader.load(NodeId.A1, directory) }
    }

    private fun nodePath(id: NodeId, file: String): Path = NodeCertificateConfig.nodeDirectory(id, directory).resolve(file)

    private fun readStore(id: NodeId): KeyStore = KeyStore.getInstance("PKCS12").also { store ->
        val password = CertificateConfig.KEYSTORE_PASSWORD.toCharArray()
        try {
            Files.newInputStream(nodePath(id, NodeCertificateConfig.KEYSTORE_FILE)).use { store.load(it, password) }
        } finally { password.fill('\u0000') }
    }

    private fun writeStore(id: NodeId, store: KeyStore) {
        val password = CertificateConfig.KEYSTORE_PASSWORD.toCharArray()
        try {
            Files.newOutputStream(nodePath(id, NodeCertificateConfig.KEYSTORE_FILE)).use { store.store(it, password) }
        } finally { password.fill('\u0000') }
    }

    companion object {
        private val generator = CertificateGenerator()
        private val material by lazy { generator.generateNodes() }
        private val unrelated by lazy { CertificateGenerator().generate() }
    }
}
