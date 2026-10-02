package ua.kpi.rgr.certificate

import ua.kpi.rgr.topology.NodeId

fun main() {
    println("========== TOPOLOGY CERTIFICATE GENERATION ==========")
    val generator = CertificateGenerator()
    val material = generator.generateNodes()
    generator.saveNodes(material)
    println("Shared Root CA: ${material.rootCertificate.subjectX500Principal}")
    println("Root certificate: ${NodeCertificateConfig.OUTPUT_DIRECTORY.resolve(CertificateConfig.ROOT_CERTIFICATE_FILE)}")
    for (id in NodeId.entries) {
        val credentials = NodeCredentialsLoader.load(id)
        val directory = NodeCertificateConfig.nodeDirectory(id)
        println("[$id] Subject: ${credentials.certificate.subjectX500Principal}")
        println("[$id] Issuer: ${credentials.certificate.issuerX500Principal}")
        println("[$id] SAN: ${credentials.certificate.subjectAlternativeNames}")
        println("[$id] Public key: ${credentials.certificate.publicKey.algorithm}")
        println("[$id] Certificate: ${directory.resolve(NodeCertificateConfig.CERTIFICATE_FILE)}")
        println("[$id] Keystore: ${directory.resolve(NodeCertificateConfig.KEYSTORE_FILE)}")
    }
    println("All six node credentials loaded and validated. Legacy demo credentials are unchanged.")
}
