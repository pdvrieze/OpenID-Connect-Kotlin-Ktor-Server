package org.mitre.openid.connect.view

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.util.pipeline.*
import org.mitre.oauth2.model.RegisteredClient
import org.mitre.oauth2.view.respondJson


/**
 *
 * Provides representation of a client's registration metadata, to be shown from the dynamic registration endpoint
 * on the client_register and rotate_secret operations.
 *
 * @author jricher
 */
suspend fun PipelineContext<Unit, ApplicationCall>.clientInformationResponseView(
    client: RegisteredClient,
    code: HttpStatusCode = HttpStatusCode.OK,
) = call.respondJson(client, code)


object ClientInformationResponseView {
    const val VIEWNAME: String = "clientInformationResponseView"
}
