plugins {
    alias(libs.plugins.kotlin.jvm)
//    id("ro.isdc.wro4j.gradle") version "1.8.0.Beta5"
}

base {
    archivesName = "openid-connect-server-ktor"
}

dependencies {
    implementation(projects.openidConnectCommon)
    api(projects.openidConnectServer)
    implementation(projects.openidConnectServerExposed)
    implementation(libs.guava) // for caching code
    implementation(libs.ktor.http)
    implementation(libs.ktor.client.core)
    implementation(libs.ktor.client.java)
    implementation(libs.ktor.client.content.negotiation)
    implementation(libs.ktor.serialization.json)
    implementation(libs.ktor.server.core)
    implementation(libs.ktor.server.content.negotiation)
    implementation(libs.ktor.server.auth.common)
    implementation(libs.ktor.server.sessions)
    implementation(libs.kotlin.wrappers.css)
//    implementation(libs.kotlin.styled)



    testImplementation(libs.junit.jupiter.api)
    testImplementation(libs.mockito.jupiter)
    testImplementation(libs.mockito.kotlin)

    testRuntimeOnly(libs.junit.jupiter.engine)
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}
