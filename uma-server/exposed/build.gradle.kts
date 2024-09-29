plugins {
    alias(libs.plugins.kotlin.jvm)
}

base {
    archivesName = "uma-server-exposed"
}

dependencies {
    api(projects.openidConnectClient)
    api(projects.openidConnectServer)
    api(projects.openidConnectServerExposed)
    api(projects.umaServer.common)
    implementation(libs.kotlinx.serialization.json)

//    implementation(libs.javax.persistence)
//    implementation(libs.javax.ann)
    implementation(libs.exposed.core)
    implementation(libs.exposed.jdbc)
    implementation(libs.exposed.javatime)

    testImplementation(libs.mockito.kotlin)
    testImplementation(libs.mockito.jupiter)
    testImplementation(libs.junit.jupiter.api)

    testRuntimeOnly(libs.junit.jupiter.engine)
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}
