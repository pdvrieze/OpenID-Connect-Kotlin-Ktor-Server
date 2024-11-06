package org.mitre.oauth2.resolver

import org.mitre.oauth2.model.AuthenticationHolder

interface AuthenticationHolderResolver {
    fun getById(id: Long): AuthenticationHolder?
}
