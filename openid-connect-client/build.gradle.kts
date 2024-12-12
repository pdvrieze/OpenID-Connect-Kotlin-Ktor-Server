plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.plugins.serialization)
}

base {
    archivesName = "openid-connect-client"
}

dependencies {
    implementation(projects.openidConnectCommon)
    implementation(projects.openidConnectCommonKtor)

    api(libs.jwt)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.caffeine)
    implementation(libs.slf4j.api)

    implementation(libs.ktor.http)

    implementation(libs.ktor.client.core)
    implementation(libs.ktor.client.java)
    implementation(libs.ktor.client.cio)

    implementation(libs.ktor.server.core)
    implementation(libs.ktor.server.auth.jwt)
    implementation(libs.ktor.server.auth.common)

    testImplementation(libs.mockito.jupiter)
    testImplementation(libs.mockito.kotlin)
    testImplementation(libs.junit.jupiter.api)

    testRuntimeOnly(libs.junit.jupiter.engine)
}

kotlin {
    compilerOptions {
        freeCompilerArgs = listOf("-Xjvm-default=all")
    }
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}
