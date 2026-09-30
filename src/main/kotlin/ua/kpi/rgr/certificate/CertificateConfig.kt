package ua.kpi.rgr.certificate

import java.nio.file.Path

object CertificateConfig {
    val OUTPUT_DIRECTORY: Path = Path.of("certificates")
    const val ROOT_CERTIFICATE_FILE = "root-ca.crt"
    const val SERVER_CERTIFICATE_FILE = "server.crt"
    const val SERVER_KEYSTORE_FILE = "server-keystore.p12"
    const val SERVER_ALIAS = "server"
    const val KEYSTORE_PASSWORD = "rgr-local-only"
    const val RSA_KEY_SIZE = 2048
    const val SIGNATURE_ALGORITHM = "SHA256withRSA"
    const val ROOT_SUBJECT = "CN=RGR Root CA"
    const val SERVER_SUBJECT = "CN=localhost"
    const val SERVER_DNS = "localhost"
    const val SERVER_IP = "127.0.0.1"
    const val ROOT_VALIDITY_DAYS = 365L * 5
    const val SERVER_VALIDITY_DAYS = 365L
}
