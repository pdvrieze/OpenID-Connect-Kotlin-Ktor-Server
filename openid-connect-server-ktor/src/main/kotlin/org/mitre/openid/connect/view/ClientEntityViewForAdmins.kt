package org.mitre.openid.connect.view

import io.ktor.http.*
import io.ktor.server.routing.*
import kotlinx.serialization.serializer
import org.mitre.oauth2.view.respondJson

/**
 *
 * View bean for full view of client entity, for admins.
 *
 * @see ClientEntityViewForUsers
 *
 * @author jricher
 */
object ClientEntityViewForAdmins {
    private val blacklistedFields: Set<String> = hashSetOf("additionalInformation")

    const val VIEWNAME: String = "clientEntityViewAdmins"
}


// TODO make this somehow different (or remove it)
suspend inline fun <reified T> RoutingContext.clientEntityViewForAdmins(
    jsonEntity: T,
    code: HttpStatusCode = HttpStatusCode.OK,
) = call.respondJson(serializer<T>(), jsonEntity, code)

