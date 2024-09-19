package org.mitre.oauth2.exception

open class AuthenticationException : RuntimeException {
    constructor(message: String? = null, cause: Throwable? = null) : super(message, cause)
    constructor(cause: Throwable?) : super(cause)
    constructor(
        message: String?,
        cause: Throwable?,
        enableSuppression: Boolean,
        writableStackTrace: Boolean
    ) : super(message, cause, enableSuppression, writableStackTrace)
}
