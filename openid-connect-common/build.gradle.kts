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
    implementation(libs.spring.webmvc)
//    implementation(libs.spring.security)
    implementation(libs.spring.oauth)
    implementation(libs.guava)
    implementation(libs.commons.httpclient)
    implementation(libs.jwt)
    implementation(libs.eclipse.persistence.core)
    implementation(libs.slf4j.api)
    implementation(libs.jaxb.api)
    implementation(libs.jaxb.bindapi)
    implementation(libs.jaxb.runtime)
    implementation(libs.servlet.api)
    implementation(libs.eclipse.persistence.core)
    implementation(libs.javax.persistence)
    implementation(libs.javax.ann)
    implementation(libs.bcprov)

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
