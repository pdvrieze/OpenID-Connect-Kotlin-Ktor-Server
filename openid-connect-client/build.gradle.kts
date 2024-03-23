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

    testImplementation(libs.junit4)
    testImplementation(libs.mockito.core)
}

tasks.named<Test>("test") {
    useJUnit()
}
