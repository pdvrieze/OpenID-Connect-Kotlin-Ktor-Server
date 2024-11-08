package org.mitre.oauth2.model.request.jpa

import org.mitre.oauth2.model.request.AuthorizationRequest
import org.mitre.oauth2.model.request.InternalForStorage

@OptIn(InternalForStorage::class)
val AuthorizationRequest.extensions: Map<String, String>
    get() = authHolderExtensions
