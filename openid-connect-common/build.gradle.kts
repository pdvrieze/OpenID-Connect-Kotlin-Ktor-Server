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
    implementation(libs.spring.core) {
        exclude("commons-logging:commons-logging")
    }
    implementation(libs.guava)
    implementation(libs.commons.httpclient)
    api(libs.jwt) // needed for base class of PKCEAlgorithm
    implementation(libs.slf4j.api)
    implementation(libs.servlet.api)
//    implementation(libs.javax.ann)
    implementation(libs.ktor.http)
    runtimeOnly(libs.bcprov)

    api(libs.kotlinx.serialization.json)

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
