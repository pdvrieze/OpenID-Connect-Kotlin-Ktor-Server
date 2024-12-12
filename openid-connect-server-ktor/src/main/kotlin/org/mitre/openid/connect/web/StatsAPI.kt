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

import io.ktor.server.auth.*
import io.ktor.server.routing.*
import org.mitre.oauth2.view.respondJson
import org.mitre.util.getLogger
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.requireUserRole
import org.mitre.web.util.statsService

object StatsAPI: KtorEndpoint {

    override fun Route.addRoutes() {
        route("/api/stats") {
            get("summary") { statsSummary() }
            authenticate {
                get("byClientid/{id}") { statsByClientId() }
            }
        }
    }

//    @Autowired
//    private lateinit var statsService: StatsService

//    @RequestMapping(value = ["summary"], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.statsSummary() {
        return call.respondJson(statsService.summaryStats)
    }

    //	@PreAuthorize("hasRole('ROLE_USER')")
    //	@RequestMapping(value = "byclientid", produces = MediaType.APPLICATION_JSON_VALUE)
    //	public String statsByClient(ModelMap m) {
    //		Map<Long, Integer> e = statsService.getByClientId();
    //
    //		m.put(JsonEntityView.ENTITY, e);
    //
    //		return JsonEntityView.VIEWNAME;
    //	}
    //
//    @PreAuthorize("hasRole('ROLE_USER')")
//    @RequestMapping(value = ["byclientid/{id}"], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.statsByClientId() {
        requireUserRole()
        val clientId = call.parameters["id"]!!
        return call.respondJson(statsService.getCountForClientId(clientId))
    }

    const val URL: String = RootController.API_URL + "/stats"

    // Logger for this class
    private val logger = getLogger<StatsAPI>()
}
