package org.mitre.oauth2.exception

class InvalidGrantException: OpenConnectException {
    constructor(message: String? = null, cause: Throwable? = null) : super(OAuthErrorCodes.INVALID_GRANT, message, cause)

    constructor(cause: Throwable?) : super(OAuthErrorCodes.INVALID_GRANT, cause)

    constructor(
        message: String?,
        cause: Throwable?,
        enableSuppression: Boolean,
        writableStackTrace: Boolean
    ) : super(OAuthErrorCodes.INVALID_GRANT, message, cause, enableSuppression, writableStackTrace)
}
