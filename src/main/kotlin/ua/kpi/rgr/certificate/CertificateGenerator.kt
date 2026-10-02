package ua.kpi.rgr.certificate

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Base64
import java.util.Date
import ua.kpi.rgr.topology.NodeId
import ua.kpi.rgr.topology.NodeDirectory

data class GeneratedCertificates(
    val rootCertificate: X509Certificate,
    val serverCertificate: X509Certificate,
    val serverKeyPair: KeyPair,
)

class CertificateGenerator {
    private val random = SecureRandom()

    fun generate(): GeneratedCertificates {
        val root = generateRoot()
        return issue(root, CertificateConfig.SERVER_DNS, CertificateConfig.SERVER_IP)
    }

    fun generateNodes(): GeneratedNodeCertificates {
        val root = generateRoot()
        val nodes = NodeId.entries.associateWith { issue(root, NodeDirectory.config(it).certificateIdentity) }
        check(nodes.values.map { it.serverCertificate.serialNumber }.toSet().size == nodes.size) {
            "Node certificate serial numbers must be distinct."
        }
        return GeneratedNodeCertificates(root.certificate, nodes)
    }

    private data class RootMaterial(val certificate: X509Certificate, val keyPair: KeyPair)

    private fun generateRoot(): RootMaterial {
        val rootKeyPair = generateKeyPair()
        val now = Instant.now()
        val notBefore = Date.from(now.minus(5, ChronoUnit.MINUTES))
        val rootName = X500Name(CertificateConfig.ROOT_SUBJECT)
        val rootSerial = serialNumber()
        val extensions = JcaX509ExtensionUtils()

        val rootBuilder = JcaX509v3CertificateBuilder(
            rootName, rootSerial, notBefore,
            Date.from(now.plus(CertificateConfig.ROOT_VALIDITY_DAYS, ChronoUnit.DAYS)),
            rootName, rootKeyPair.public,
        )
        rootBuilder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        rootBuilder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
        rootBuilder.addExtension(Extension.subjectKeyIdentifier, false, extensions.createSubjectKeyIdentifier(rootKeyPair.public))
        rootBuilder.addExtension(Extension.authorityKeyIdentifier, false, extensions.createAuthorityKeyIdentifier(rootKeyPair.public))
        val signer = JcaContentSignerBuilder(CertificateConfig.SIGNATURE_ALGORITHM).build(rootKeyPair.private)
        val converter = JcaX509CertificateConverter()
        val rootCertificate = converter.getCertificate(rootBuilder.build(signer))
        rootCertificate.checkValidity()
        rootCertificate.verify(rootCertificate.publicKey)
        return RootMaterial(rootCertificate, rootKeyPair)
    }

    private fun issue(root: RootMaterial, identity: String, ip: String? = null): GeneratedCertificates {
        val rootCertificate = root.certificate
        val serverKeyPair = generateKeyPair()
        val now = Instant.now()
        val notBefore = Date.from(now.minus(5, ChronoUnit.MINUTES))
        val rootName = X500Name(rootCertificate.subjectX500Principal.name)
        var serverSerial = serialNumber()
        while (serverSerial == rootCertificate.serialNumber) serverSerial = serialNumber()
        val extensions = JcaX509ExtensionUtils()
        val signer = JcaContentSignerBuilder(CertificateConfig.SIGNATURE_ALGORITHM).build(root.keyPair.private)
        val converter = JcaX509CertificateConverter()
        val serverBuilder = JcaX509v3CertificateBuilder(
            rootName, serverSerial, notBefore,
            Date.from(now.plus(CertificateConfig.SERVER_VALIDITY_DAYS, ChronoUnit.DAYS)),
            X500Name("CN=$identity"), serverKeyPair.public,
        )
        serverBuilder.addExtension(Extension.basicConstraints, true, BasicConstraints(false))
        serverBuilder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment))
        serverBuilder.addExtension(Extension.extendedKeyUsage, false, ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth))
        serverBuilder.addExtension(
            Extension.subjectAlternativeName, false,
            GeneralNames(buildList {
                add(GeneralName(GeneralName.dNSName, identity))
                if (ip != null) add(GeneralName(GeneralName.iPAddress, ip))
            }.toTypedArray()),
        )
        serverBuilder.addExtension(Extension.subjectKeyIdentifier, false, extensions.createSubjectKeyIdentifier(serverKeyPair.public))
        serverBuilder.addExtension(Extension.authorityKeyIdentifier, false, extensions.createAuthorityKeyIdentifier(rootCertificate.publicKey))
        val serverCertificate = converter.getCertificate(serverBuilder.build(signer))
        return GeneratedCertificates(rootCertificate, serverCertificate, serverKeyPair).also(::verify)
    }

    fun verify(material: GeneratedCertificates) {
        val root = material.rootCertificate
        val server = material.serverCertificate
        root.checkValidity()
        root.verify(root.publicKey)
        server.checkValidity()
        server.verify(root.publicKey)
        check(root.subjectX500Principal == root.issuerX500Principal) { "Root CA must be self-issued." }
        check(root.basicConstraints >= 0) { "Root certificate must be a CA." }
        check(server.basicConstraints == -1) { "Server certificate must not be a CA." }
        check(server.issuerX500Principal == root.subjectX500Principal) { "Server issuer must match Root CA." }
        check(server.publicKey.encoded.contentEquals(material.serverKeyPair.public.encoded)) {
            "Server certificate must contain the generated server public key."
        }
    }

    fun save(material: GeneratedCertificates, directory: Path = CertificateConfig.OUTPUT_DIRECTORY) {
        verify(material)
        Files.createDirectories(directory)
        writePem(material.rootCertificate, directory.resolve(CertificateConfig.ROOT_CERTIFICATE_FILE))
        writePem(material.serverCertificate, directory.resolve(CertificateConfig.SERVER_CERTIFICATE_FILE))
        saveKeystore(material, directory.resolve(CertificateConfig.SERVER_KEYSTORE_FILE), CertificateConfig.SERVER_ALIAS)
    }

    fun saveNodes(material: GeneratedNodeCertificates, directory: Path = NodeCertificateConfig.OUTPUT_DIRECTORY) {
        require(material.nodes.keys == NodeId.entries.toSet()) { "All six node credentials are required." }
        material.nodes.values.forEach {
            require(it.rootCertificate.encoded.contentEquals(material.rootCertificate.encoded)) { "All nodes must share one Root CA." }
            verify(it)
        }
        Files.createDirectories(directory)
        writePem(material.rootCertificate, directory.resolve(CertificateConfig.ROOT_CERTIFICATE_FILE))
        for ((id, credentials) in material.nodes) {
            val nodeDirectory = NodeCertificateConfig.nodeDirectory(id, directory)
            Files.createDirectories(nodeDirectory)
            writePem(credentials.serverCertificate, nodeDirectory.resolve(NodeCertificateConfig.CERTIFICATE_FILE))
            saveKeystore(credentials, nodeDirectory.resolve(NodeCertificateConfig.KEYSTORE_FILE), NodeCertificateConfig.ALIAS)
        }
    }

    private fun saveKeystore(material: GeneratedCertificates, path: Path, alias: String) {
        val password = CertificateConfig.KEYSTORE_PASSWORD.toCharArray()
        try {
            val keyStore = KeyStore.getInstance("PKCS12")
            keyStore.load(null, password)
            keyStore.setKeyEntry(
                alias, material.serverKeyPair.private, password,
                arrayOf(material.serverCertificate, material.rootCertificate),
            )
            Files.newOutputStream(path).use {
                keyStore.store(it, password)
            }
        } finally {
            password.fill('\u0000')
        }
    }

    private fun generateKeyPair(): KeyPair = KeyPairGenerator.getInstance("RSA").apply {
        initialize(CertificateConfig.RSA_KEY_SIZE, random)
    }.generateKeyPair()

    private fun serialNumber(): BigInteger = BigInteger(159, random).add(BigInteger.ONE)

    private fun writePem(certificate: X509Certificate, path: Path) {
        val encoded = Base64.getMimeEncoder(64, byteArrayOf(10)).encodeToString(certificate.encoded)
        Files.writeString(path, "-----BEGIN CERTIFICATE-----\n$encoded\n-----END CERTIFICATE-----\n", StandardCharsets.US_ASCII)
    }
}
