package org.mitre.oauth2.model

import kotlinx.serialization.Serializable

@JvmInline
@Serializable
value class GrantedAuthority(val authority: String)
