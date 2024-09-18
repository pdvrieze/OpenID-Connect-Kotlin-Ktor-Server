plugins {
    alias(libs.plugins.kotlin.jvm)
    `java-library`
//    id("ro.isdc.wro4j.gradle") version "1.8.0.Beta5"
}

base {
    archivesName = "openid-connect-server-ktor-html"
}

dependencies {
    implementation(projects.openidConnectCommon)
    implementation(projects.openidConnectServerKtor)

    implementation(libs.ktor.server.html.builder)
    implementation(libs.kotlinx.html)
    implementation(libs.kotlin.wrappers.css)

    testImplementation(libs.junit.jupiter.api)

    testRuntimeOnly(libs.junit.jupiter.engine)
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}
