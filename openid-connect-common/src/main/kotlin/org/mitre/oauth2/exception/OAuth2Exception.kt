package org.mitre.oauth2.exception

open class OAuth2Exception: AuthenticationException {
    val oauth2ErrorCode: ErrorCodes

    constructor(oauthErrorCode: ErrorCodes, message: String? = null, cause: Throwable? = null) : super(message, cause) {
        this.oauth2ErrorCode = oauthErrorCode
    }

    constructor(oauthErrorCode: ErrorCodes, cause: Throwable?) : super(cause) {
        this.oauth2ErrorCode = oauthErrorCode
    }

    constructor(
        oauthErrorCode: ErrorCodes,
        message: String?,
        cause: Throwable?,
        enableSuppression: Boolean,
        writableStackTrace: Boolean
    ) : super(message, cause, enableSuppression, writableStackTrace) {
        this.oauth2ErrorCode = oauthErrorCode
    }
}

