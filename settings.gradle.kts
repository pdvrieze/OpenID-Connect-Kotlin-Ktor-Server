//pluginManagement {
//    plugins {
//        kotlin("jvm") version "1.9.23"
//    }
//}
plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.5.0"
}

/*
plugins {
    // Apply the foojay-resolver plugin to allow automatic download of JDKs
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.7.0"
}
*/

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

dependencyResolutionManagement {
    repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS
    repositories {
        mavenCentral()
        maven { url = uri("https://maven.pkg.jetbrains.space/kotlin/p/kotlin/kotlin-js-wrappers") }
    }
}

rootProject.name = "OpenID-Connect-Kotlin-Ktor-Server"

include("openid-connect-common")
include("openid-connect-spring")
include("openid-connect-server")
include("openid-connect-client")
//include("openid-connect-server-webapp")
//include("openid-connect-server-jpaSpring")
include("openid-connect-server-exposed")
include("openid-connect-server-ktor")
include("openid-connect-server-ktor-html")
include("uma-server:common")
//include("uma-server:jpa")
include("uma-server:exposed")
//include("uma-server-webapp")
include("uma-server-ktor")
