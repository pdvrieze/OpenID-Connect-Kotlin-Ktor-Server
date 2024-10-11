/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
 *
 * Portions copyright 2011-2013 The MITRE Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.mitre.openid.connect.web

import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import io.ktor.util.pipeline.*
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.web.OpenIdSessionStorage
import org.mitre.web.htmlAboutView
import org.mitre.web.htmlContactView
import org.mitre.web.htmlHomeView
import org.mitre.web.htmlLoginView
import org.mitre.web.htmlManageView
import org.mitre.web.htmlStatsView
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.openIdContext
import org.mitre.web.util.requireRole
import org.mitre.web.util.statsService
import org.mitre.web.util.update
import java.net.URI
import java.util.*

/**
 * @author Michael Jett <mjett></mjett>@mitre.org>
 */
object RootController: KtorEndpoint {

    override fun Route.addRoutes() {
        get("login") { login() }
        authenticate(optional = true) {
            get("", "home", "index") { showHomePage()}
            get("about") { showAboutPage() }
            get("stats") { showStatsPage() }
            get("contact") { showContactPage() }
        }

        authenticate {
            get("manage/{...}") { showClientManager() }
        }
        post("login") { doLogin() }
//        authenticate("form") {
//        }
    }

    suspend fun PipelineContext<Unit, ApplicationCall>.showHomePage() {
        return htmlHomeView()
    }

    suspend fun PipelineContext<Unit, ApplicationCall>.showAboutPage() {
        return htmlAboutView()
    }

    suspend fun PipelineContext<Unit, ApplicationCall>.showStatsPage() {
        return htmlStatsView(statsService.summaryStats)
    }

    suspend fun PipelineContext<Unit, ApplicationCall>.showContactPage() {
        return htmlContactView()
    }

    suspend fun PipelineContext<Unit, ApplicationCall>.showClientManager() {
        requireRole(GrantedAuthority.ROLE_USER) { return }
        return htmlManageView()
    }

    suspend fun PipelineContext<Unit, ApplicationCall>.login() {
        return htmlLoginView(null, null, call.request.queryParameters["redirect_uri"])
    }

    suspend fun PipelineContext<Unit, ApplicationCall>.doLogin() {
        val formParams = call.receiveParameters()

        val userName = formParams["username"]
        val password = formParams["password"]

        if (!userName.isNullOrBlank() && !password.isNullOrBlank() &&
            openIdContext.checkCredential(UserPasswordCredential(userName, password))) {

            val principal = UserIdPrincipal(userName)
            call.authentication.principal(principal)
            call.sessions.update<OpenIdSessionStorage> { it?.copy(principal = principal) ?: OpenIdSessionStorage(principal = principal) }
            val redirect = formParams["redirect"]?.takeIf { ! URI.create(it).isAbsolute } ?: "/"
            return call.respondRedirect(redirect)
        }

        val locales = call.request.acceptLanguageItems().map { Locale(it.value) }
        val error = openIdContext.messageSource.resolveCode("login.error", locales)?.format(null)
        return htmlLoginView(formParams["username"], error, formParams["redirect"])
    }


    const val API_URL: String = "api"
}
