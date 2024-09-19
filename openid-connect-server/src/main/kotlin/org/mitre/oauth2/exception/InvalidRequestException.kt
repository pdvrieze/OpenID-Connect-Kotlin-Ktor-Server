package org.mitre.oauth2.exception

class InvalidRequestException : OAuth2Exception {
    constructor(message: String? = null, cause: Throwable? = null) : super(ErrorCodes.INVALID_REQUEST, message, cause)

    constructor(cause: Throwable?) : super(ErrorCodes.INVALID_REQUEST, cause)

    constructor(
        message: String?,
        cause: Throwable?,
        enableSuppression: Boolean,
        writableStackTrace: Boolean
    ) : super(ErrorCodes.INVALID_REQUEST, message, cause, enableSuppression, writableStackTrace)
}
