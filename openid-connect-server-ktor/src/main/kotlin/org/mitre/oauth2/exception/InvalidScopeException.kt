package org.mitre.oauth2.exception

class InvalidScopeException: OpenConnectException {
    constructor(message: String? = null, cause: Throwable? = null) : super(OAuthErrorCodes.INVALID_SCOPE, message, cause)
    constructor(cause: Throwable?) : super(OAuthErrorCodes.INVALID_SCOPE, cause)
    constructor(
        message: String?,
        cause: Throwable?,
        enableSuppression: Boolean,
        writableStackTrace: Boolean
    ) : super(OAuthErrorCodes.INVALID_SCOPE, message, cause, enableSuppression, writableStackTrace)
}
