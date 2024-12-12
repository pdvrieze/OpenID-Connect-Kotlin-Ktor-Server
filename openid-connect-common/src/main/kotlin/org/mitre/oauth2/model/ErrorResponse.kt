package org.mitre.oauth2.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
class ErrorResponse(
    val error: String,
    @SerialName("error_description")
    val errorDescription: String,
)
