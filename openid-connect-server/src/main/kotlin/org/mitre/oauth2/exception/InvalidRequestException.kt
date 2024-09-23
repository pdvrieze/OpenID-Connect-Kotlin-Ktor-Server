package org.mitre.oauth2.exception

class InvalidRequestException : OAuth2Exception {
    constructor(message: String? = null, cause: Throwable? = null) : super(INVALID_REQUEST_CODE, message, cause)

    constructor(cause: Throwable?) : super(INVALID_REQUEST_CODE, cause)

    constructor(
        message: String?,
        cause: Throwable?,
        enableSuppression: Boolean,
        writableStackTrace: Boolean
    ) : super(INVALID_REQUEST_CODE, message, cause, enableSuppression, writableStackTrace)

    companion object {
        @JvmStatic
        val INVALID_REQUEST_CODE = object: OAuthErrorCode {
            override val code: String get() = "invalid_request"
            override val rawHttpCode: Int get() = 400
            override val scopes: Array<out OAuthErrorCode.Scope> = arrayOf(
                OAuthErrorCode.Scope.ACCESS_TOKEN_ISSUE,
                OAuthErrorCode.Scope.BEARER_TOKEN_USE,
                OAuthErrorCode.Scope.ACCESS_REQUEST
            )
        }
    }

}
