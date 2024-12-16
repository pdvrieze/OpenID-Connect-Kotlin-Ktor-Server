/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
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
package org.mitre.uma.web

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.mitre.oauth2.view.respondJson
import org.mitre.openid.connect.client.service.getIssuer
import org.mitre.openid.connect.client.service.impl.WebfingerIssuerService
import org.mitre.openid.connect.web.RootController
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.config
import org.mitre.web.util.requireUserRole
import org.mitre.web.util.userInfoService

/**
 * @author jricher
 */
//@Controller
//@RequestMapping("/" + UserClaimSearchHelper.URL)
//@PreAuthorize("hasRole('ROLE_USER')")
object UserClaimSearchHelper: KtorEndpoint {
    override fun Route.addRoutes() {
        route("/api/emailsearch") {
            authenticate {
                get { search() }
            }
        }
    }

    private val webfingerIssuerService = WebfingerIssuerService()


    //    @RequestMapping(method = [RequestMethod.GET], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.search() {
        val auth = requireUserRole().getOrElse { return }
        // check locally first
        val email = call.request.queryParameters["email"] ?: return call.respond(HttpStatusCode.BadRequest)

        val localUser = userInfoService.getByEmailAddress(email)

        if (localUser != null) {

            val e = buildJsonArray {
                addJsonObject {
                    putJsonArray("issuer") { add(config.issuer) }
                    put("name", "email")
                    put("value", localUser.email)
                }
                addJsonObject {
                    putJsonArray("issuer") { add(config.issuer) }
                    put("name", "email_verified")
                    put("value", localUser.emailVerified)
                }
                addJsonObject {
                    putJsonArray("issuer") { add(config.issuer) }
                    put("name", "sub")
                    put("value", localUser.subject)
                }
            }
            return call.respondJson(e)
        }
        // otherwise do a webfinger lookup

        val resp = webfingerIssuerService.getIssuer(call.request)

        if (resp?.issuer == null) {
            return call.respond(HttpStatusCode.NotFound)
        }

        // we found an issuer, return that
        val res = buildJsonArray {
            addJsonObject {
                putJsonArray("issuer") { add(resp.issuer) }
                put("name", "email")
                put("value", email)
            }
            addJsonObject {
                putJsonArray("issuer") { add(resp.issuer) }
                put("name", "email_verified")
                put("value", true)
            }
        }
        return call.respondJson(res)
    }

    const val URL: String = RootController.API_URL + "/emailsearch"
}
