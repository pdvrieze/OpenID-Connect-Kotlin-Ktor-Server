plugins {
    `java-library`
    alias(libs.plugins.kotlin.jvm)
//    id("ro.isdc.wro4j.gradle") version "1.8.0.Beta5"
}

base {
    archivesName = "openid-connect-server-jpa"
}

dependencies {
    implementation(projects.openidConnectCommon)
    implementation(projects.openidConnectServer)

    implementation(libs.slf4j.api)
    implementation(libs.guava)
    implementation(libs.commons.httpclient)

//    implementation(libs.persistence)
    implementation(libs.javax.persistence)
    implementation(libs.javax.ann)

    implementation(libs.spring.tx)
    implementation(libs.spring.orm) {
        exclude("commons-logging:commons-logging")
    }

    implementation(libs.spring.webmvc)
    implementation(libs.spring.oauth)



    testImplementation(libs.mockito.jupiter)
    testImplementation(libs.mockito.kotlin)
    testImplementation(libs.junit.jupiter.api)
//    testImplementation(libs.spring.core)

    testImplementation(libs.eclipse.persistence.jpa)
    testImplementation(libs.eclipse.persistence.core)

    testRuntimeOnly(libs.junit.jupiter.engine)
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}
