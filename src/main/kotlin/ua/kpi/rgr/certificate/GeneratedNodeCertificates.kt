package ua.kpi.rgr.certificate

import ua.kpi.rgr.topology.NodeId
import java.security.cert.X509Certificate

data class GeneratedNodeCertificates(
    val rootCertificate: X509Certificate,
    val nodes: Map<NodeId, GeneratedCertificates>,
)
