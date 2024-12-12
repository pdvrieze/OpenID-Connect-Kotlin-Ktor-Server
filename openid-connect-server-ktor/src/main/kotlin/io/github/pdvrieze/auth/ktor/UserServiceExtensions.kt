package io.github.pdvrieze.auth.ktor

import io.github.pdvrieze.auth.AuthFactor
import io.github.pdvrieze.auth.DirectUserAuthentication
import io.github.pdvrieze.auth.UserService
import io.ktor.server.auth.*

fun UserService.createUserDirectAuthentication(auth: UserPasswordCredential): DirectUserAuthentication? = when {
    verifyCredentials(auth.name, auth.password) -> createUserDirectAuthentication(auth.name, AuthFactor.PASSWORD)
    else -> null
}
