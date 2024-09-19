package org.mitre.oauth2.exception

class InsufficientScopeException: OAuth2Exception {
    constructor(message: String? = null, cause: Throwable? = null) : super(ErrorCodes.INSUFFICIENT_SCOPE, message, cause)
    constructor(cause: Throwable?) : super(ErrorCodes.INSUFFICIENT_SCOPE, cause)
    constructor(
        message: String?,
        cause: Throwable?,
        enableSuppression: Boolean,
        writableStackTrace: Boolean
    ) : super(ErrorCodes.INSUFFICIENT_SCOPE, message, cause, enableSuppression, writableStackTrace)

}
