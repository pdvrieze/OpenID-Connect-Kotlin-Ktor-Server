package org.mitre.oauth2.exception

class InsufficientScopeException: OAuth2Exception {
    constructor(message: String? = null, cause: Throwable? = null) : super(OAuthErrorCodes.INSUFFICIENT_SCOPE, message, cause)
    constructor(cause: Throwable?) : super(OAuthErrorCodes.INSUFFICIENT_SCOPE, cause)
    constructor(
        message: String?,
        cause: Throwable?,
        enableSuppression: Boolean,
        writableStackTrace: Boolean
    ) : super(OAuthErrorCodes.INSUFFICIENT_SCOPE, message, cause, enableSuppression, writableStackTrace)

}
