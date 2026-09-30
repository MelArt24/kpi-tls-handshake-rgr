plugins {
    kotlin("jvm") version "2.0.20"
}

group = "ua.kpi.rgr"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}
kotlin {
    jvmToolchain(17)
}

tasks.register<JavaExec>("runServer") {
    group = "application"
    description = "Runs the plaintext TCP server."
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("ua.kpi.rgr.server.ServerMainKt")
}

tasks.register<JavaExec>("runClient") {
    group = "application"
    description = "Runs the plaintext TCP client."
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("ua.kpi.rgr.client.ClientMainKt")
}
