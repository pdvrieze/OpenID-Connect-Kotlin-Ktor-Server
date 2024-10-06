plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.plugins.jpa)
    alias(libs.plugins.kotlin.plugins.spring)
    alias(libs.plugins.kotlin.plugins.serialization)
}

base {
    archivesName = "openid-connect-common-ktor"
}

dependencies {
    implementation(projects.openidConnectCommon)

    implementation(libs.ktor.server.core)

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
