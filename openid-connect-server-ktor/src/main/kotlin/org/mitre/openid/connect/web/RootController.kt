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
import io.ktor.server.routing.*
import io.ktor.util.pipeline.*
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.web.htmlAboutView
import org.mitre.web.htmlContactView
import org.mitre.web.htmlHomeView
import org.mitre.web.htmlManageView
import org.mitre.web.htmlStatsView
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.requireRole
import org.mitre.web.util.statsService

/**
 * @author Michael Jett <mjett></mjett>@mitre.org>
 */
class RootController: KtorEndpoint {

    override fun Route.addRoutes() {
        get("", "home", "index") { showHomePage()}
        get("about") { showAboutPage() }
        get("stats") { showStatsPage() }
        get("contact") { showContactPage() }

        authenticate {
            get("manage/{...}") {
                showClientManager()
            }
        }
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

    companion object {
        const val API_URL: String = "api"
    }
}
