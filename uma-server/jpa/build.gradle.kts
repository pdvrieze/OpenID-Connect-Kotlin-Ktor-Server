plugins {
    alias(libs.plugins.kotlin.jvm)
}

base {
    archivesName = "uma-server-jpa"
}

dependencies {
    implementation(projects.openidConnectServer)
    implementation(projects.openidConnectClient)
    api(projects.umaServer.common)

    implementation(libs.guava)
    implementation(libs.servlet.api)
    implementation(libs.slf4j.api)
    implementation(libs.spring.webmvc)
    implementation(libs.spring.tx)
    implementation(libs.kotlinx.serialization.json)
/*
    implementation(libs.spring.core) {
        exclude("commons-logging:commons-logging")
    }
    implementation(libs.spring.webmvc)
//    implementation(libs.spring.security)
    implementation(libs.spring.oauth)

    implementation(libs.commons.httpclient)
    implementation(libs.jwt)
    implementation(libs.persistence)
    implementation(libs.jaxb.api)
    implementation(libs.jaxb.bindapi)
    implementation(libs.jaxb.runtime)
    implementation(libs.jackson.databind)
    implementation(libs.jackson.annotations)
    implementation(libs.servlet.api)
    implementation(libs.persistence)
    implementation(libs.javax.persistence)
    implementation(libs.javax.ann)
    implementation(libs.bcprov)
*/
    implementation(libs.javax.persistence)
//    implementation(libs.javax.ann)

    testImplementation(libs.mockito.kotlin)
    testImplementation(libs.mockito.jupiter)
    testImplementation(libs.junit.jupiter.api)

    testRuntimeOnly(libs.junit.jupiter.engine)
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}
