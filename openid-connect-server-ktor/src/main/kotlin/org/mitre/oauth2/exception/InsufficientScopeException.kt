package org.mitre.oauth2.exception

import org.mitre.oauth2.exception.OAuthErrorCodes.INSUFFICIENT_SCOPE

class InsufficientScopeException: OAuth2Exception {
    constructor(message: String? = null, cause: Throwable? = null) : super(INSUFFICIENT_SCOPE, message, cause)
    constructor(cause: Throwable?) : super(INSUFFICIENT_SCOPE, cause)
    constructor(
        message: String?,
        cause: Throwable?,
        enableSuppression: Boolean,
        writableStackTrace: Boolean
    ) : super(INSUFFICIENT_SCOPE, message, cause, enableSuppression, writableStackTrace)
}
