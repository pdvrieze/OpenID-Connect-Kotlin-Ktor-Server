package org.mitre.oauth2.token

import io.ktor.http.*

interface TokenRequest {

    /** TODO: Make immutable */
    var scope: Set<String>?
    val requestParameters: Parameters
}
