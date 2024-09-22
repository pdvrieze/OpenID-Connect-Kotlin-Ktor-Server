package org.mitre.openid.connect.exception

import org.springframework.http.HttpStatus

/**
 * Thrown by utility methods when a client fails to validate. Contains information
 * to be returned.
 * @author jricher
 */
class ValidationException(
    var error: String,
    var errorDescription: String,
    var status: HttpStatus
) : Exception() {
    override fun toString(): String {
        return "ValidationException [error=$error, errorDescription=$errorDescription, status=$status]"
    }

    companion object {
        private const val serialVersionUID = 1820497072989294627L
    }
}
