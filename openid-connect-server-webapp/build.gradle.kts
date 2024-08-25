plugins {
    alias(libs.plugins.kotlin.jvm)
    war
//    id("ro.isdc.wro4j.gradle") version "1.8.0.Beta5"
}

base {
    archivesName = "openid-connect-server-webapp"
}

dependencies {
    implementation(projects.openidConnectCommon)
    implementation(projects.openidConnectServer)
/*
    implementation(libs.spring.core) {
        exclude("commons-logging:commons-logging")
    }
    implementation(libs.spring.webmvc)
//    implementation(libs.spring.security)
    implementation(libs.spring.oauth)

    implementation(libs.guava)
    implementation(libs.commons.httpclient)
    implementation(libs.jwt)
    implementation(libs.persistence)
    implementation(libs.slf4j.api)
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

    testImplementation(libs.junit.jupiter.api)

    testRuntimeOnly(libs.junit.jupiter.engine)
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}
