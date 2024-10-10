plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.plugins.spring)
//    alias(libs.plugins.kotlin.plugins.jpa)
    alias(libs.plugins.kotlin.plugins.serialization)
}

base {
    archivesName = "openid-connect-server"
}

dependencies {
    api(projects.openidConnectCommon)
    api(projects.openidConnectCommonKtor)

    implementation(libs.slf4j.api)
    implementation(libs.caffeine)
    implementation(libs.jwt)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.bcprov)

    testImplementation(libs.mockito.jupiter)
    testImplementation(libs.mockito.kotlin)
    testImplementation(libs.spring.test)
    testImplementation(libs.junit.jupiter.api)

    testRuntimeOnly(libs.junit.jupiter.engine)
    testRuntimeOnly(libs.eclipse.persistence.jpa)
    testRuntimeOnly(libs.eclipse.persistence.core)
}

kotlin {
    compilerOptions {
        freeCompilerArgs = listOf("-Xjvm-default=all")
    }
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}
