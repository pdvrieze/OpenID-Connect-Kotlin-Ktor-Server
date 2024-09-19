package org.mitre.oauth2.exception

class InvalidScopeException: OpenConnectException {
    constructor(message: String? = null, cause: Throwable? = null) : super(ErrorCodes.INVALID_SCOPE, message, cause)
    constructor(cause: Throwable?) : super(ErrorCodes.INVALID_SCOPE, cause)
    constructor(
        message: String?,
        cause: Throwable?,
        enableSuppression: Boolean,
        writableStackTrace: Boolean
    ) : super(ErrorCodes.INVALID_SCOPE, message, cause, enableSuppression, writableStackTrace)
}
