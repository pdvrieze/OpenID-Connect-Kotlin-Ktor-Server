plugins {
    alias(libs.plugins.kotlin.jvm)
}

base {
    archivesName = "openid-connect-client"
}

dependencies {
    implementation(projects.openidConnectCommon)
    implementation(projects.openidConnectCommonKtor)

    api(libs.spring.oauth)
    implementation(libs.ktor.server.auth.jwt)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.guava)
    api(libs.jwt)
//    implementation(libs.commons.httpclient)
    implementation(libs.slf4j.api)
//    implementation(libs.servlet.api)
    implementation(libs.ktor.http)
    implementation(libs.ktor.client.core)
    implementation(libs.ktor.client.java)
    implementation(libs.ktor.client.cio)
    implementation(libs.ktor.server.core)
    implementation(libs.ktor.server.auth.common)
    implementation("io.ktor:ktor-client-cio-jvm:2.3.10")
    implementation("io.ktor:ktor-client-java:2.3.10")

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
