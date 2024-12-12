package io.github.pdvrieze.auth

import kotlinx.serialization.Serializable

@Serializable
sealed interface ClientAuthentication : Authentication, ScopedAuthentication {
    val clientId: String
}

