package org.mitre.oauth2.exception

import io.ktor.http.*

enum class OAuthErrorCodes(
    override val code: String,
    val httpCode: HttpStatusCode?,
    override vararg val scopes: OAuthErrorCode.Scope,
): OAuthErrorCode {

    /**
     * The request is missing a required parameter, includes an unsupported parameter or parameter
     * value, repeats the same parameter, uses more than one method for including an access token,
     * or is otherwise malformed.  The resource server SHOULD respond with the HTTP 400 (Bad
     * Request) status code.
     */
    INVALID_REQUEST("invalid_request", HttpStatusCode.BadRequest, OAuthErrorCode.Scope.ACCESS_TOKEN_ISSUE, OAuthErrorCode.Scope.BEARER_TOKEN_USE, OAuthErrorCode.Scope.ACCESS_REQUEST),

    /**
     * Client authentication failed (e.g., unknown client, no client authentication included,
     * or unsupported authentication method). The authorization server MAY return a HTTP 401
     * (Unauthorized) status code to indicate which HTTP authentication schemes are supported.
     * If the client attempted to authenticate via the "Authorization" request header field,
     * the authorization server MUST respond with a HTTP 401 (Unauthorized) status code and
     * include the "WWW-Authenticate" response header field matching the authentication scheme
     * used by the client.
     */
    INVALID_CLIENT("invalid_client", HttpStatusCode.BadRequest, OAuthErrorCode.Scope.ACCESS_TOKEN_ISSUE),

    /**
     * The provided authorization grant (e.g., authorization code, resource owner credentials)
     * or refresh token is invalid, expired, revoked, does not match the redirection URI used
     * in the authorization request, or was issued to another client.
     */
    INVALID_GRANT("invalid_grant", HttpStatusCode.BadRequest, OAuthErrorCode.Scope.ACCESS_TOKEN_ISSUE),

    /**
     * The access token provided is expired, revoked, malformed, or invalid for other reasons.
     * The resource SHOULD respond with the HTTP 401 (Unauthorized) status code.  The client MAY
     * request a new access token and retry the protected resource request.
     *
     * @see RFC7650 (for bearer access token)
     */
    INVALID_TOKEN("invalid_token", HttpStatusCode.Unauthorized, OAuthErrorCode.Scope.BEARER_TOKEN_USE),

    /**
     * The client is not authorized to request an authorization code using this method.
     */
    UNAUTHORIZED_CLIENT("unauthorized_client", HttpStatusCode.BadRequest, OAuthErrorCode.Scope.ACCESS_TOKEN_ISSUE, OAuthErrorCode.Scope.ACCESS_REQUEST),

    /**
     * The authorization grant type is not supported by the authorization server.
     */
    UNSUPPORTED_GRANT_TYPE("unsupported_grant_type", HttpStatusCode.BadRequest, OAuthErrorCode.Scope.ACCESS_TOKEN_ISSUE),

    /**
     * The request requires higher privileges than provided by the access token.  The resource
     * server SHOULD respond with the HTTP 403 (Forbidden) status code and MAY include the
     * "scope" attribute with the scope necessary to access the protected resource.
     *
     * @see RFC6750 (for bearer access token)
     */
    INSUFFICIENT_SCOPE("insufficient_scope", HttpStatusCode.Forbidden, OAuthErrorCode.Scope.BEARER_TOKEN_USE),

    /**
     * The authorization server does not support obtaining an authorization code using this method.
     */
    UNSUPPORTED_RESPONSE_TYPE("unsupported_response_type", HttpStatusCode.BadRequest, OAuthErrorCode.Scope.ACCESS_REQUEST),

    /**
     * The resource owner or authorization server denied the request.
     */
    ACCESS_DENIED("access_denied", HttpStatusCode.Forbidden, OAuthErrorCode.Scope.ACCESS_REQUEST),

    /**
     * The authorization server does not support the revocation of the presented token type.  That
     * is, the client tried to revoke an access token on a server not supporting this feature.
     *
     * @see RFC 7009 Section 2.2.1
     */
    UNSUPPORTED_TOKEN_TYPE("unsupported_token_type", HttpStatusCode.BadRequest, OAuthErrorCode.Scope.TOKEN_REVOCATION),

    /**
     * The requested scope is invalid, unknown, or malformed.
     */
    INVALID_SCOPE("invalid_scope", HttpStatusCode.BadRequest, OAuthErrorCode.Scope.ACCESS_TOKEN_ISSUE, OAuthErrorCode.Scope.ACCESS_REQUEST),

    /**
     * The value of one or more redirection URIs is invalid.
     * @see RFC 7591 Section 3.2.2
     */
    INVALID_REDIRECT_URI("invalid_redirect_uri", HttpStatusCode.BadRequest, OAuthErrorCode.Scope.DYNAMIC_REGISTRATION),

    /**
     * The value of one of the client metadata fields is invalid and the server has rejected this
     * request.  Note that an authorization server MAY choose to substitute a valid value for any
     * requested parameter of a client's metadata.
     */
    INVALID_CLIENT_METADATA("invalid_client_metadata", HttpStatusCode.BadRequest, OAuthErrorCode.Scope.DYNAMIC_REGISTRATION),

    /**
     * The software statement presented is invalid.
     */
    INVALID_SOFTWARE_STATEMENT("invalid_software_statement", HttpStatusCode.BadRequest, OAuthErrorCode.Scope.DYNAMIC_REGISTRATION),

    /**
     * The software statement presented is not approved for use by this authorization server.
     */
    UNAPPROVED_SOFTWARE_STATEMENT("unapproved_software_statement", HttpStatusCode.BadRequest, OAuthErrorCode.Scope.DYNAMIC_REGISTRATION),

    /**
     * The authorization server encountered an unexpected condition that prevented it from fulfilling
     * the request. (This error code is needed because a 500 Internal Server Error HTTP status code
     * cannot be returned to the client via an HTTP redirect.)
     */
    SERVER_ERROR("server_error", HttpStatusCode.InternalServerError, OAuthErrorCode.Scope.ACCESS_REQUEST),

    /**
     * The authorization server is currently unable to handle the request due to a temporary overloading
     * or maintenance of the server.  (This error code is needed because a 503 Service Unavailable HTTP
     * status code cannot be returned to the client via an HTTP redirect.)
     */
    TEMPORARILY_UNAVAILABLE("temporarily_unavailable", HttpStatusCode.ServiceUnavailable, OAuthErrorCode.Scope.ACCESS_REQUEST),
    ;

    constructor(code: String, vararg scopes: OAuthErrorCode.Scope): this(code, null, *scopes)

    override val rawHttpCode: Int
        get() = httpCode?.value ?: 500

    override fun toString(): String {
        return code
    }
}

val OAuthErrorCode.httpCode: HttpStatusCode?
    get() = when(this) {
        is OAuthErrorCodes -> httpCode
        else -> rawHttpCode?.let{ HttpStatusCode.fromValue(it) }
    }
