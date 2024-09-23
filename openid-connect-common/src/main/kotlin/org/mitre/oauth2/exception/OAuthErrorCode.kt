package org.mitre.oauth2.exception

interface OAuthErrorCode {
    val code: String
    val rawHttpCode: Int?
    val scopes: Array<out Scope>

    enum class Scope { ACCESS_TOKEN_ISSUE, BEARER_TOKEN_USE, ACCESS_REQUEST, TOKEN_REVOCATION, DYNAMIC_REGISTRATION }
}
