package org.mitre.web.util

import io.github.pdvrieze.auth.Authentication
import io.github.pdvrieze.auth.ClientAuthentication
import io.github.pdvrieze.auth.ClientJwtAuthentication
import io.github.pdvrieze.auth.UserAuthentication
import io.ktor.http.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.mitre.oauth2.exception.AuthenticationException
import org.mitre.oauth2.model.GrantedAuthority

private suspend fun RoutingContext.getAuthOrRespondUnauthorized(): Result<Authentication> {
    return when(val authentication = resolveAuthenticatedUser()) {
        null -> kotlin.runCatching { call.respondWithError(HttpStatusCode.Unauthorized) }
        else -> Result.success(authentication)
    }
}

suspend fun RoutingContext.requireRole(requiredRole: GrantedAuthority): Result<Authentication> {
    return getAuthOrRespondUnauthorized().mapCatching {
        when (requiredRole) {
            is UserAuthentication -> it

            else -> call.respondWithError(HttpStatusCode.Forbidden)
        }
    }
}

suspend fun RoutingContext.requireUserRole(requiredRole: GrantedAuthority): Result<UserAuthentication> {
    return getAuthOrRespondUnauthorized().mapCatching { authentication ->
        when {
            authentication is UserAuthentication && requiredRole in authentication.authorities -> authentication
            else -> call.respondWithError(HttpStatusCode.Forbidden)
        }
    }
}

suspend fun RoutingContext.requireUserRole(): Result<UserAuthentication> {
    return getAuthOrRespondUnauthorized().mapCatching { authentication ->
        when (authentication) {
            is UserAuthentication -> authentication

            else -> call.respondWithError(HttpStatusCode.Forbidden)
        }
    }
}

suspend fun RoutingContext.requireUserScope(a: GrantedAuthority, vararg scopes: String, action: () -> Nothing): Result<UserAuthentication> {
    return requireUserScope(*scopes)
}

suspend fun RoutingContext.requireUserScope(vararg scopes: String): Result<UserAuthentication> {
    return getAuthOrRespondUnauthorized().mapCatching { authentication ->
        when {
            authentication is UserAuthentication && !scopes.any { !authentication.hasScope(it) }
                -> authentication

            else -> call.respondWithError(HttpStatusCode.Forbidden)
        }
    }
}

suspend fun RoutingContext.requireClientRole(): Result<ClientAuthentication> {
    val authentication = getAuthOrRespondUnauthorized().mapCatching { authentication ->
        when (authentication) {
            is ClientAuthentication -> authentication

            else -> call.respondWithError(HttpStatusCode.Forbidden)
        }
    }
    return authentication
}

suspend fun RoutingContext.requireClientTokenScope(vararg scopes: String): Result<ClientJwtAuthentication> {
    return getAuthOrRespondUnauthorized().mapCatching { authentication ->
        when {
            authentication is ClientJwtAuthentication && !scopes.any { !authentication.hasScope(it) }
                -> authentication

            else -> call.respondWithError(HttpStatusCode.Forbidden)
        }
    }
}

suspend fun RoutingContext.requireScope(
    scope: String,
): Result<Authentication> {
    return getAuthOrRespondUnauthorized().mapCatching { authentication ->
        when {
            authentication.hasScope(scope) -> authentication

            else -> call.respondWithError(HttpStatusCode.Forbidden)
        }
    }
}

suspend fun RoutingContext.requireClientOrAdminRole(): Result<Authentication> {
    return runCatching {
        val authentication = resolveAuthenticatedUser() ?: call.respondWithError(HttpStatusCode.Unauthorized)

        if (authentication !is ClientAuthentication &&
            (authentication !is UserAuthentication || GrantedAuthority.ROLE_ADMIN !in authentication.authorities)) {
            call.respondWithError(HttpStatusCode.Forbidden)
        }
        authentication
    }
}

suspend fun RoutingCall.respondWithError(status: HttpStatusCode): Nothing {
    require(! status.isSuccess())
    respond(status)
    throw AuthenticationException("Not authorized")
}
