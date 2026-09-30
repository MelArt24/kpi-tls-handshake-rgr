package ua.kpi.rgr.certificate

import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

data class ServerCredentials(
    val privateKey: PrivateKey,
    val certificate: X509Certificate,
    val certificateChain: List<X509Certificate>,
)

object ServerCredentialsLoader {
    fun load(directory: Path = CertificateConfig.OUTPUT_DIRECTORY): ServerCredentials {
        val certificate = CertificateLoader.loadServer(directory)
        val keystorePath = directory.resolve(CertificateConfig.SERVER_KEYSTORE_FILE)
        CertificateLoader.requireFile(keystorePath)
        val password = CertificateConfig.KEYSTORE_PASSWORD.toCharArray()
        try {
            val keyStore = KeyStore.getInstance("PKCS12")
            Files.newInputStream(keystorePath).use { keyStore.load(it, password) }
            val alias = CertificateConfig.SERVER_ALIAS
            if (!keyStore.containsAlias(alias) || !keyStore.entryInstanceOf(alias, KeyStore.PrivateKeyEntry::class.java)) {
                throw IOException("Server keystore must contain a private-key entry with alias '$alias'.")
            }
            val key = keyStore.getKey(alias, password)
            if (key !is RSAPrivateKey || key.algorithm != "RSA") {
                throw IOException("Server keystore private key must be RSA.")
            }
            val chain = keyStore.getCertificateChain(alias)
            if (chain.isNullOrEmpty() || chain.any { it !is X509Certificate }) {
                throw IOException("Server keystore must contain an X.509 certificate chain.")
            }
            val publicKey = certificate.publicKey
            if (!chain[0].encoded.contentEquals(certificate.encoded) || publicKey !is RSAPublicKey || key.modulus != publicKey.modulus) {
                throw IOException(
                    "Server certificate and private-key keystore do not belong to the same generated credential set. " +
                        "Run: ./gradlew.bat generateCertificates",
                )
            }
            return ServerCredentials(key, certificate, chain.map { it as X509Certificate })
        } catch (error: GeneralSecurityException) {
            throw IOException("Cannot load server PKCS#12 credentials. Run: ./gradlew.bat generateCertificates", error)
        } finally {
            password.fill('\u0000')
        }
    }
}
