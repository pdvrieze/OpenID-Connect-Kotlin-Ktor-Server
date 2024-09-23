package org.mitre.oauth2.exception

open class OpenConnectException : OAuth2Exception {
    constructor(oauth2ErrorCode: OAuthErrorCode, message: String? = null, cause: Throwable? = null) : super(oauth2ErrorCode, message, cause)

    constructor(oauth2ErrorCode: OAuthErrorCode, cause: Throwable?) : super(oauth2ErrorCode, cause)

    constructor(
        oauth2ErrorCode: OAuthErrorCode,
        message: String?,
        cause: Throwable?,
        enableSuppression: Boolean,
        writableStackTrace: Boolean
    ) : super(oauth2ErrorCode, message, cause, enableSuppression, writableStackTrace)
}
