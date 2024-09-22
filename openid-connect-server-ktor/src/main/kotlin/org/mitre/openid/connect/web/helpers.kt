package org.mitre.openid.connect.web

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.util.pipeline.*
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.web.util.openIdContext

fun PipelineContext<Unit, ApplicationCall>.clientRegistrationUri(client: OAuthClientDetails) =
    URLBuilder(openIdContext.config.issuer).apply { path("register", client.clientId!!) }.buildString()
