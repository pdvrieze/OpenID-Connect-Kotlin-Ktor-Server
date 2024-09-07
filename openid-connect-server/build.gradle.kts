plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.plugins.spring)
    alias(libs.plugins.kotlin.plugins.jpa)
    alias(libs.plugins.kotlin.plugins.serialization)
}

base {
    archivesName = "openid-connect-server"
}

dependencies {
    api(projects.openidConnectSpring)
    implementation(libs.servlet.api)
    implementation(libs.spring.tx)
    implementation(libs.spring.orm) {
        exclude("commons-logging:commons-logging")
    }
    implementation(libs.spring.webmvc)
    implementation(libs.spring.oauth)
    implementation(libs.commons.httpclient)
    implementation(libs.slf4j.api)
    implementation(libs.eclipse.persistence.core)
    implementation(libs.eclipse.persistence.jpa)
    implementation(libs.hsqldb)
    implementation(libs.commons.io)
    implementation(libs.guava)
    implementation(libs.jwt)
    implementation(libs.kotlinx.serialization.json)

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
