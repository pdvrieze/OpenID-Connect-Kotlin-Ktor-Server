package org.mitre.openid.connect.exception

import io.ktor.http.*
import org.mitre.oauth2.exception.OAuthErrorCode
import org.mitre.oauth2.exception.httpCode
import org.mitre.web.JsonErrorException

class ValidationException: JsonErrorException {
    constructor(
        error: OAuthErrorCode,
        message: String?,
        httpStatus: HttpStatusCode = error.httpCode ?: HttpStatusCode.BadRequest,
    ) : super(error, message, httpStatus)

    constructor(code: String, message: String?, httpStatus: HttpStatusCode) : super(code, message, httpStatus)
}
