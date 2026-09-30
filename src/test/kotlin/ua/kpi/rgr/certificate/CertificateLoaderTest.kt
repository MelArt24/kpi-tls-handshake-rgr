package ua.kpi.rgr.certificate

import org.junit.jupiter.api.io.TempDir
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class CertificateLoaderTest {
    @TempDir
    lateinit var directory: Path

    @Test
    fun `loads generated PEM root and server using JVM APIs`() {
        val material = CertificateGenerator().generate()
        CertificateGenerator().save(material, directory)
        assertEquals(material.rootCertificate, CertificateLoader.loadRoot(directory))
        assertEquals(material.serverCertificate, CertificateLoader.loadServer(directory))
    }

    @Test
    fun `missing credentials report generation command`() {
        for (file in listOf(CertificateConfig.ROOT_CERTIFICATE_FILE, CertificateConfig.SERVER_CERTIFICATE_FILE)) {
            val error = assertFailsWith<IOException> { CertificateLoader.load(directory.resolve(file)) }
            assertTrue(error.message.orEmpty().contains("./gradlew.bat generateCertificates"))
        }
    }

    @Test
    fun `malformed certificate file is rejected clearly`() {
        val file = directory.resolve("invalid.crt")
        Files.writeString(file, "Not a certificate")
        val error = assertFailsWith<IOException> { CertificateLoader.load(file) }
        assertTrue(error.message.orEmpty().contains("Cannot load X.509 certificate"))
    }
}
