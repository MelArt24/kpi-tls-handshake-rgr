package ua.kpi.rgr.certificate

import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

object CertificateLoader {
    fun requireFile(path: Path, generationTask: String = "generateCertificates") {
        if (!Files.isRegularFile(path)) {
            throw IOException("Certificate file is missing: $path. Run: ./gradlew.bat $generationTask")
        }
    }

    fun loadRoot(directory: Path = CertificateConfig.OUTPUT_DIRECTORY): X509Certificate =
        load(directory.resolve(CertificateConfig.ROOT_CERTIFICATE_FILE))

    fun loadServer(directory: Path = CertificateConfig.OUTPUT_DIRECTORY): X509Certificate =
        load(directory.resolve(CertificateConfig.SERVER_CERTIFICATE_FILE))

    fun load(path: Path, generationTask: String = "generateCertificates"): X509Certificate {
        requireFile(path, generationTask)
        try {
            return Files.newInputStream(path).use {
                CertificateFactory.getInstance("X.509").generateCertificate(it) as X509Certificate
            }
        } catch (error: CertificateException) {
            throw IOException("Cannot load X.509 certificate from $path: ${error.message}", error)
        }
    }
}
