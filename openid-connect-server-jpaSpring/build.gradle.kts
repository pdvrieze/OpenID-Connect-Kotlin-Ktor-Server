plugins {
    `java-library`
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.plugins.spring)
    alias(libs.plugins.kotlin.plugins.jpa)
    alias(libs.plugins.kotlin.plugins.serialization)
//    id("ro.isdc.wro4j.gradle") version "1.8.0.Beta5"
}

base {
    archivesName = "openid-connect-server-spring"
}

dependencies {
    implementation(projects.openidConnectCommon)
    implementation(projects.openidConnectServer)
    implementation(projects.openidConnectSpring)

    implementation(libs.slf4j.api)
    implementation(libs.caffeine)
    implementation(libs.commons.httpclient)
    implementation(libs.servlet.api)
    implementation(libs.kotlinx.serialization.json)

    implementation(libs.eclipse.persistence.core)
    implementation(libs.eclipse.persistence.jpa)
    implementation(libs.javax.persistence)
    implementation(libs.javax.ann)

    implementation(libs.spring.tx)
    implementation(libs.spring.orm) {
        exclude("commons-logging:commons-logging")
    }

    implementation(libs.kotlinx.coroutines)

    implementation(libs.spring.webmvc)
    implementation(libs.spring.oauth)


    testImplementation(libs.mockito.jupiter)
    testImplementation(libs.mockito.kotlin)
    testImplementation(libs.spring.test)
    testImplementation(libs.junit.jupiter.api)

    testImplementation(libs.eclipse.persistence.jpa)
//    testImplementation(libs.eclipse.persistence.core)

    testRuntimeOnly(libs.junit.jupiter.engine)
//    testRuntimeOnly(libs.eclipse.persistence.jpa)
    testRuntimeOnly(libs.eclipse.persistence.core)
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}
