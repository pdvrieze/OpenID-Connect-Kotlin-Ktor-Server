package org.mitre.oauth2.exception

class InvalidClientException: OpenConnectException {
    constructor(message: String? = null, cause: Throwable? = null) : super(ErrorCodes.INVALID_CLIENT, message, cause)
    constructor(cause: Throwable?) : super(ErrorCodes.INVALID_CLIENT, cause)
    constructor(
        message: String?,
        cause: Throwable?,
        enableSuppression: Boolean,
        writableStackTrace: Boolean
    ) : super(ErrorCodes.INVALID_CLIENT, message, cause, enableSuppression, writableStackTrace)
}
