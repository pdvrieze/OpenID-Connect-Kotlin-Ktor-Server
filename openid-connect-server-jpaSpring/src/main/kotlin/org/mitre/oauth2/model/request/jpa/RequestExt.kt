package org.mitre.oauth2.model.request.jpa

import org.mitre.oauth2.model.request.AuthorizationRequest

val AuthorizationRequest.extensions: Map<String, String>
    get() = authHolderExtensions
