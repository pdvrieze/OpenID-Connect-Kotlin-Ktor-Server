plugins {
    alias(libs.plugins.kotlin.jvm)
}

base {
    archivesName = "uma-server-exposed"
}

dependencies {
    api(projects.umaServer.common)
    implementation(libs.kotlinx.serialization.json)

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
