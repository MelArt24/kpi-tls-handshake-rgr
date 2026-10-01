plugins {
    kotlin("jvm") version "2.0.20"
    kotlin("plugin.serialization") version "2.0.20"
}

group = "ua.kpi.rgr"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.bouncycastle:bcpkix-jdk18on:1.83")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    testImplementation(kotlin("test-junit5"))
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.10.1")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.10.1")
}

tasks.test {
    useJUnitPlatform()
}
kotlin {
    jvmToolchain(17)
}

tasks.register<JavaExec>("runServer") {
    group = "application"
    description = "Runs the educational handshake and encrypted chat server."
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("ua.kpi.rgr.server.ServerMainKt")
    standardInput = System.`in`
    jvmArgs("-Dfile.encoding=UTF-8")
}

tasks.register<JavaExec>("runClient") {
    group = "application"
    description = "Runs the educational handshake and encrypted chat client."
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("ua.kpi.rgr.client.ClientMainKt")
    standardInput = System.`in`
    jvmArgs("-Dfile.encoding=UTF-8")
}

tasks.register<JavaExec>("generateCertificates") {
    group = "application"
    description = "Generates the local educational Root CA and server credentials."
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("ua.kpi.rgr.certificate.CertificateGeneratorMainKt")
    workingDir = rootProject.projectDir
}
