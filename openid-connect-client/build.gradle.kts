plugins {
    alias(libs.plugins.kotlin.jvm)
}

base {
    archivesName = "openid-connect-client"
}

dependencies {
    api(projects.openidConnectSpring)
    api(libs.spring.oauth)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.guava)
    api(libs.jwt)
    implementation(libs.commons.httpclient)
    implementation(libs.slf4j.api)
    implementation(libs.servlet.api)
    implementation(libs.javax.ann)
    implementation(libs.ktor.http)

    testImplementation(libs.mockito.jupiter)
    testImplementation(libs.mockito.kotlin)
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
