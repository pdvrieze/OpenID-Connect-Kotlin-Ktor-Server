plugins {
    alias(libs.plugins.kotlin.jvm)
}

base {
    archivesName = "openid-connect-client"
}

dependencies {
    api(projects.openidConnectCommon)
    api(libs.spring.oauth)
    implementation(libs.gson)
    implementation(libs.guava)
    api(libs.jwt)
    implementation(libs.commons.httpclient)
    implementation(libs.slf4j.api)
    implementation(libs.servlet.api)
    implementation(libs.javax.ann)

    testImplementation(libs.hamcrest.core)
    testImplementation(libs.mockito.core)
    testImplementation(libs.mockito.jupiter)
    testImplementation(libs.junit.jupiter.api)

    testRuntimeOnly(libs.junit.jupiter.engine)
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}
