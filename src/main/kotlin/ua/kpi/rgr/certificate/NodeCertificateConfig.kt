package ua.kpi.rgr.certificate

import ua.kpi.rgr.topology.NodeId
import java.nio.file.Path

object NodeCertificateConfig {
    val OUTPUT_DIRECTORY: Path = CertificateConfig.OUTPUT_DIRECTORY.resolve("topology")
    const val CERTIFICATE_FILE = "certificate.crt"
    const val KEYSTORE_FILE = "keystore.p12"
    const val ALIAS = "node"

    fun nodeDirectory(id: NodeId, directory: Path = OUTPUT_DIRECTORY): Path =
        directory.resolve("nodes").resolve(id.directoryName)
}
