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
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.IOException
import java.math.BigInteger
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ServerCertificateValidatorTest {
    @Test
    fun `matching Root CA authenticates localhost with RSA server usages`() {
        val server = materialA.serverCertificate
        ServerCertificateValidator.validate(server, materialA.rootCertificate, "localhost")
        assertEquals(-1, server.basicConstraints)
        assertEquals("RSA", server.publicKey.algorithm)
        assertTrue(server.keyUsage[2])
        assertTrue(server.extendedKeyUsage.contains("1.3.6.1.5.5.7.3.1"))
    }

    @Test
    fun `different Root CA rejects certificate despite identical issuer and localhost subject`() {
        assertEquals(materialA.rootCertificate.subjectX500Principal, materialB.rootCertificate.subjectX500Principal)
        val error = assertFailsWith<IOException> {
            ServerCertificateValidator.validate(materialA.serverCertificate, materialB.rootCertificate, "localhost")
        }
        assertTrue(error.message.orEmpty().contains("PKIX server certificate validation failed"))
    }

    @Test
    fun `IP host uses matching IP SAN`() {
        ServerCertificateValidator.validate(materialA.serverCertificate, materialA.rootCertificate, "127.0.0.1")
    }

    @Test
    fun `unrelated DNS and IP hosts are rejected`() {
        for (host in listOf("example.com", "127.0.0.2")) {
            val error = assertFailsWith<IOException> {
                ServerCertificateValidator.validate(materialA.serverCertificate, materialA.rootCertificate, host)
            }
            assertTrue(error.message.orEmpty().contains("SAN does not identify"))
        }
    }

    @Test
    fun `non CA trust anchor is rejected`() {
        val error = assertFailsWith<IOException> {
            ServerCertificateValidator.validate(materialA.serverCertificate, materialA.serverCertificate, "localhost")
        }
        assertTrue(error.message.orEmpty().contains("not marked as a CA"))
    }

    @Test
    fun `CA certificate cannot serve as a server certificate`() {
        val error = assertFailsWith<IOException> {
            ServerCertificateValidator.validate(testCertificate(ca = true), testRoot, "localhost")
        }
        assertTrue(error.message.orEmpty().contains("must not be a CA"))
    }

    @Test
    fun `missing key encipherment is rejected`() {
        val error = assertFailsWith<IOException> {
            ServerCertificateValidator.validate(testCertificate(usage = KeyUsage.digitalSignature), testRoot, "localhost")
        }
        assertTrue(error.message.orEmpty().contains("keyEncipherment"))
    }

    @Test
    fun `wrong or missing EKU is rejected`() {
        for (eku in listOf(KeyPurposeId.id_kp_clientAuth, null)) {
            val error = assertFailsWith<IOException> {
                ServerCertificateValidator.validate(testCertificate(eku = eku), testRoot, "localhost")
            }
            assertTrue(error.message.orEmpty().contains("serverAuth"))
        }
    }

    @Test
    fun `localhost CN does not substitute for absent or mismatched SAN`() {
        for (dns in listOf("example.com", null)) {
            val error = assertFailsWith<IOException> {
                ServerCertificateValidator.validate(testCertificate(dns = dns), testRoot, "localhost")
            }
            assertTrue(error.message.orEmpty().contains("SAN does not identify"))
        }
    }

    @Test
    fun `expired server certificate fails PKIX`() {
        val error = assertFailsWith<IOException> {
            ServerCertificateValidator.validate(testCertificate(expired = true), testRoot, "localhost")
        }
        assertTrue(error.message.orEmpty().contains("PKIX server certificate validation failed"))
    }

    private fun testCertificate(
        ca: Boolean = false,
        usage: Int = KeyUsage.digitalSignature or KeyUsage.keyEncipherment,
        eku: KeyPurposeId? = KeyPurposeId.id_kp_serverAuth,
        dns: String? = "localhost",
        expired: Boolean = false,
    ): X509Certificate {
        val now = Instant.now()
        val builder = JcaX509v3CertificateBuilder(
            X500Name("CN=Test Root"), BigInteger.valueOf(2), Date.from(now.minusSeconds(3600)),
            Date.from(if (expired) now.minusSeconds(60) else now.plusSeconds(3600)),
            X500Name("CN=localhost"), materialA.serverKeyPair.public,
        )
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(ca))
        builder.addExtension(Extension.keyUsage, true, KeyUsage(usage))
        if (eku != null) builder.addExtension(Extension.extendedKeyUsage, false, ExtendedKeyUsage(eku))
        if (dns != null) builder.addExtension(
            Extension.subjectAlternativeName, false, GeneralNames(GeneralName(GeneralName.dNSName, dns)),
        )
        val signer = JcaContentSignerBuilder("SHA256withRSA").build(materialB.serverKeyPair.private)
        return JcaX509CertificateConverter().getCertificate(builder.build(signer))
    }

    companion object {
        private val materialA by lazy { CertificateGenerator().generate() }
        private val materialB by lazy { CertificateGenerator().generate() }
        // Test-only issuer retains a key so negative leaf variants can be signed legitimately.
        private val testRoot by lazy {
            val now = Instant.now()
            val name = X500Name("CN=Test Root")
            val builder = JcaX509v3CertificateBuilder(
                name, BigInteger.ONE, Date.from(now.minusSeconds(3600)), Date.from(now.plusSeconds(3600)),
                name, materialB.serverKeyPair.public,
            )
            builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
            builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
            val signer = JcaContentSignerBuilder("SHA256withRSA").build(materialB.serverKeyPair.private)
            JcaX509CertificateConverter().getCertificate(builder.build(signer))
        }
    }
}
