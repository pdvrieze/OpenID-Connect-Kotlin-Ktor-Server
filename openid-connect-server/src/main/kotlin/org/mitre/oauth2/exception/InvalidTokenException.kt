package org.mitre.oauth2.exception

class InvalidTokenException: OpenConnectException {
    constructor(message: String? = null, cause: Throwable? = null) : super(ErrorCodes.INVALID_TOKEN, message, cause)
    constructor(cause: Throwable?) : super(ErrorCodes.INVALID_TOKEN, cause)
    constructor(
        message: String?,
        cause: Throwable?,
        enableSuppression: Boolean,
        writableStackTrace: Boolean
    ) : super(ErrorCodes.INVALID_TOKEN, message, cause, enableSuppression, writableStackTrace)
}

