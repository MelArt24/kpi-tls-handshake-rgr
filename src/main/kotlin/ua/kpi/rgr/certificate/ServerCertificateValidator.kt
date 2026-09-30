package ua.kpi.rgr.certificate

import java.io.IOException
import java.security.GeneralSecurityException
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate

object ServerCertificateValidator {
    fun validate(server: X509Certificate, root: X509Certificate, expectedHost: String) {
        try {
            root.checkValidity()
            if (root.basicConstraints < 0) throw IOException("Trusted Root CA is not marked as a CA.")
            if (root.subjectX500Principal != root.issuerX500Principal) {
                throw IOException("Trusted Root CA must be self-issued.")
            }
            root.verify(root.publicKey)
        } catch (error: GeneralSecurityException) {
            throw IOException("Trusted Root CA sanity check failed: ${error.message}", error)
        }

        try {
            val path = CertificateFactory.getInstance("X.509").generateCertPath(listOf(server))
            val parameters = PKIXParameters(setOf(TrustAnchor(root, null))).apply {
                isRevocationEnabled = false
            }
            CertPathValidator.getInstance("PKIX").validate(path, parameters)
        } catch (error: GeneralSecurityException) {
            throw IOException("PKIX server certificate validation failed: ${error.message}", error)
        }

        try {
            if (server.basicConstraints != -1) throw IOException("Server certificate must not be a CA.")
            if (server.publicKey.algorithm != "RSA") throw IOException("Server certificate public key must be RSA.")
            if (server.keyUsage?.getOrNull(2) != true) {
                throw IOException("Server certificate must permit keyEncipherment.")
            }
            if (server.extendedKeyUsage?.contains("1.3.6.1.5.5.7.3.1") != true) {
                throw IOException("Server certificate must permit serverAuth extended key usage.")
            }
            val ipHost = expectedHost.matches(Regex("[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+")) || ':' in expectedHost
            val sanType = if (ipHost) 7 else 2
            val matches = server.subjectAlternativeNames.orEmpty().any {
                it[0] == sanType && (it[1] as? String)?.equals(expectedHost, ignoreCase = true) == true
            }
            if (!matches) throw IOException("Server certificate SAN does not identify expected host '$expectedHost'.")
        } catch (error: GeneralSecurityException) {
            throw IOException("Server certificate usage or SAN validation failed: ${error.message}", error)
        }
    }
}
