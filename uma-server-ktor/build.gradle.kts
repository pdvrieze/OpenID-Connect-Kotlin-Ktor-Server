
//val ktor_version: String by project
//val kotlin_version: String by project
//val logback_version: String by project

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.plugins.serialization)
    alias(libs.plugins.ktor)
}

group = "io.github.pdvrieze.auth"
version = "0.0.1"

application {
    mainClass.set("io.pdvrieze.github.auth.ktor.ApplicationKt")

    val isDevelopment: Boolean = project.ext.has("development")
    applicationDefaultJvmArgs = listOf("-Dio.ktor.development=$isDevelopment")
}


dependencies {
    implementation(projects.openidConnectCommon)
    implementation(projects.openidConnectServer)
    implementation(projects.openidConnectServerExposed)
    implementation(projects.openidConnectServerKtor)
    implementation(projects.openidConnectServerKtorHtml)
    implementation(projects.umaServer.exposed)

    implementation(libs.ktor.server.core)
    implementation(libs.ktor.server.auth.common)
    implementation(libs.ktor.server.auth.jwt)
    implementation(libs.ktor.server.host.common)
    implementation(libs.ktor.server.resources)
    implementation(libs.ktor.server.compression)
    implementation(libs.ktor.server.content.negotiation)
    implementation(libs.ktor.serialization.json)
    implementation(libs.ktor.server.html.builder)
    implementation(libs.ktor.server.netty)
    implementation(libs.kotlinx.html)
    implementation(libs.kotlin.wrappers.css)
    implementation(libs.exposed.core)
    implementation(libs.exposed.jdbc)
    implementation(libs.exposed.javatime)
    implementation(libs.h2)
    implementation(libs.logback)

    implementation(libs.jwt)

    // DEPRECATED
//    implementation(libs.spring.oauth)


    testImplementation(libs.ktor.server.tests)
    testImplementation(libs.kotlin.test.junit)
}
