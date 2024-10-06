plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.plugins.jpa)
    alias(libs.plugins.kotlin.plugins.spring)
    alias(libs.plugins.kotlin.plugins.serialization)
}

base {
    archivesName = "openid-connect-common"
}

dependencies {
    api(libs.jwt) // needed for base class of PKCEAlgorithm
    implementation(libs.caffeine)
    implementation(libs.kotlinx.coroutines)
    implementation(libs.slf4j.api)

    implementation(libs.kotlinx.serialization.json)

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
