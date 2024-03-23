plugins {
    alias(libs.plugins.kotlin.jvm)
}

base {
    archivesName = "openid-connect-server"
}

dependencies {
    implementation(projects.openidConnectCommon)
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
    implementation(libs.gson)
    implementation(libs.guava)
    implementation(libs.jwt)

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
    implementation(libs.gson)
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

    testImplementation(libs.junit4)
    testImplementation(libs.mockito.core)
    testImplementation(libs.spring.test)
//    testImplementation(libs.hamcrest.all)
    testImplementation(libs.hamcrest.core)
}

tasks.named<Test>("test") {
    useJUnit()
}
