package org.mitre.oauth2.model.request

import kotlinx.serialization.Serializable

@Serializable
data class CodeChallenge(val challenge: String, val method: String)
