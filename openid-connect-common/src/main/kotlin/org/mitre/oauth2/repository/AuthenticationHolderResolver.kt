package org.mitre.oauth2.repository

import org.mitre.oauth2.model.AuthenticationHolderEntity

interface AuthenticationHolderResolver {
    fun getById(id: Long): AuthenticationHolderEntity?
}
