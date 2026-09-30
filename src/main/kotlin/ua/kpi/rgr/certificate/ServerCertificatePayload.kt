package ua.kpi.rgr.certificate

import ua.kpi.rgr.protocol.ProtocolMessage
import java.io.ByteArrayInputStream
import java.io.IOException
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

object ServerCertificatePayload {
    const val FIELD = "serverCertificate"

    fun encode(certificate: X509Certificate): String = Base64.getEncoder().encodeToString(certificate.encoded)

    fun decode(message: ProtocolMessage): X509Certificate {
        val encoded = message.payload[FIELD]
            ?: throw IOException("SERVER_HELLO is missing the '$FIELD' payload field.")
        val bytes = try {
            Base64.getDecoder().decode(encoded)
        } catch (error: IllegalArgumentException) {
            throw IOException("Invalid Base64 serverCertificate in SERVER_HELLO.", error)
        }
        try {
            val certificate = ByteArrayInputStream(bytes).use {
                CertificateFactory.getInstance("X.509").generateCertificate(it) as X509Certificate
            }
            if (!certificate.encoded.contentEquals(bytes)) {
                throw IOException("serverCertificate must contain exactly one DER X.509 certificate.")
            }
            return certificate
        } catch (error: CertificateException) {
            throw IOException("Invalid X.509 serverCertificate: ${error.message}", error)
        }
    }
}
