package ua.kpi.rgr.certificate

import java.nio.file.Files
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

fun main() {
    println("========== CERTIFICATE GENERATION ==========\n")
    val generator = CertificateGenerator()
    println("[CA] Generating RSA-2048 Root CA and independent server key pairs...")
    val material = generator.generate()
    println("[CA] Subject: ${material.rootCertificate.subjectX500Principal}")
    println("[CA] Signature algorithm: ${material.rootCertificate.sigAlgName}")
    println("[CA] Valid until: ${material.rootCertificate.notAfter}")
    println("[SERVER] Subject: ${material.serverCertificate.subjectX500Principal}")
    println("[SERVER] Issuer: ${material.serverCertificate.issuerX500Principal}")
    println("[SERVER] Signature algorithm: ${material.serverCertificate.sigAlgName}")
    println("[SERVER] SAN: ${material.serverCertificate.subjectAlternativeNames}")
    println("[SERVER] Valid until: ${material.serverCertificate.notAfter}")
    println("[VERIFY] Root CA self-signature and server certificate signature: OK")

    val directory = CertificateConfig.OUTPUT_DIRECTORY
    generator.save(material, directory)
    val factory = CertificateFactory.getInstance("X.509")
    val root = Files.newInputStream(directory.resolve(CertificateConfig.ROOT_CERTIFICATE_FILE)).use {
        factory.generateCertificate(it) as X509Certificate
    }
    val server = Files.newInputStream(directory.resolve(CertificateConfig.SERVER_CERTIFICATE_FILE)).use {
        factory.generateCertificate(it) as X509Certificate
    }
    root.checkValidity()
    root.verify(root.publicKey)
    server.checkValidity()
    server.verify(root.publicKey)
    val password = CertificateConfig.KEYSTORE_PASSWORD.toCharArray()
    try {
        val keyStore = KeyStore.getInstance("PKCS12")
        Files.newInputStream(directory.resolve(CertificateConfig.SERVER_KEYSTORE_FILE)).use { keyStore.load(it, password) }
        check(keyStore.isKeyEntry(CertificateConfig.SERVER_ALIAS)) { "Missing server private key entry." }
        check(keyStore.getKey(CertificateConfig.SERVER_ALIAS, password).encoded.contentEquals(material.serverKeyPair.private.encoded))
        val chain = keyStore.getCertificateChain(CertificateConfig.SERVER_ALIAS)
        check(chain.size == 2 && chain[0] == server && chain[1] == root) { "Incorrect server certificate chain." }
    } finally {
        password.fill('\u0000')
    }
    println("[VERIFY] Saved X.509 certificates and PKCS#12 private key/chain: OK")
    println("\nGenerated:")
    for (file in listOf(CertificateConfig.ROOT_CERTIFICATE_FILE, CertificateConfig.SERVER_CERTIFICATE_FILE, CertificateConfig.SERVER_KEYSTORE_FILE)) {
        println(directory.resolve(file))
    }
}
