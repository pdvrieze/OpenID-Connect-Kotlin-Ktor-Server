plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.plugins.jpa)
    alias(libs.plugins.kotlin.plugins.spring)
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
    implementation(libs.gson)
    implementation(libs.jaxb.api)
    implementation(libs.jaxb.bindapi)
    implementation(libs.jaxb.runtime)
    implementation(libs.jackson.databind)
    implementation(libs.jackson.annotations)
    implementation(libs.servlet.api)
    implementation(libs.eclipse.persistence.core)
    implementation(libs.javax.persistence)
    implementation(libs.javax.ann)
    implementation(libs.bcprov)

    testImplementation(libs.junit.jupiter.api)
    testRuntimeOnly(libs.junit.jupiter.engine)
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}
