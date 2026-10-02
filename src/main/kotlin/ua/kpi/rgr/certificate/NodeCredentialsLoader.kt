package ua.kpi.rgr.certificate

import ua.kpi.rgr.topology.NodeDirectory
import ua.kpi.rgr.topology.NodeId
import java.io.IOException
import java.nio.file.Path
import java.security.cert.X509Certificate

object NodeCredentialsLoader {
    fun loadRoot(directory: Path = NodeCertificateConfig.OUTPUT_DIRECTORY): X509Certificate =
        CertificateLoader.load(directory.resolve(CertificateConfig.ROOT_CERTIFICATE_FILE), "generateNodeCertificates")

    fun load(id: NodeId, directory: Path = NodeCertificateConfig.OUTPUT_DIRECTORY): ServerCredentials {
        val nodeDirectory = NodeCertificateConfig.nodeDirectory(id, directory)
        val credentials = ServerCredentialsLoader.loadFiles(
            nodeDirectory.resolve(NodeCertificateConfig.CERTIFICATE_FILE),
            nodeDirectory.resolve(NodeCertificateConfig.KEYSTORE_FILE),
            NodeCertificateConfig.ALIAS,
            "generateNodeCertificates",
        )
        val root = loadRoot(directory)
        if (credentials.certificateChain.size != 2 ||
            !credentials.certificateChain.last().encoded.contentEquals(root.encoded)) {
            throw IOException("Node $id certificate chain must contain the shared topology Root CA. Run: ./gradlew.bat generateNodeCertificates")
        }
        ServerCertificateValidator.validate(credentials.certificate, root, NodeDirectory.config(id).certificateIdentity)
        return credentials
    }
}
