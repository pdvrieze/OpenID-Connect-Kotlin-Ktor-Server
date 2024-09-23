package org.mitre.openid.connect.filter

import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.util.*
import io.ktor.util.pipeline.*
import org.mitre.oauth2.exception.InvalidClientException
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.convert.OAuth2Request
import org.mitre.openid.connect.request.ConnectRequestParameters
import org.mitre.openid.connect.service.LoginHintExtracter
import org.mitre.openid.connect.service.impl.RemoveLoginHintsWithHTTP
import org.mitre.openid.connect.web.AuthenticationTimeStamper
import org.mitre.util.getLogger
import org.mitre.web.util.clientService
import org.mitre.web.util.openIdContext
import org.mitre.web.util.redirectResolver
import org.mitre.web.util.resolveAuthenticatedUser
import java.net.URISyntaxException
import java.util.*

/**
 * @author jricher
 */
class AuthorizationRequestFilter {
//    @Autowired
//    private lateinit var authRequestFactory: OAuth2RequestFactory

//    @Autowired
//    private lateinit var clientService: ClientDetailsEntityService

//    @Autowired
//    private lateinit var redirectResolver: RedirectResolver

//    @Autowired(required = false)
    private val loginHintExtracter: LoginHintExtracter = RemoveLoginHintsWithHTTP()

//    var requestMatcher: RequestMatcher = AntPathRequestMatcher("/authorize")

//    override fun doFilter(req: ServletRequest, res: ServletResponse, chain: FilterChain) {
    private suspend fun PipelineContext<Any, ApplicationCall>.doIntercept(subject: Any) {
        // skip everything that's not an authorize URL
        if (!call.request.path().startsWith("/authorize")) return // skip intercept


        try {
            // we have to create our own auth request in order to get at all the parmeters appropriately
            val authRequest: OAuth2Request?

            var client: OAuthClientDetails? = null

            val params = call.request.queryParameters.let { if (call.request.httpMethod == HttpMethod.Post) it+call.receiveParameters() else it }

            authRequest = openIdContext.authRequestFactory.createAuthorizationRequest(params)

            if (!authRequest.clientId.isNullOrEmpty()) {
                client = clientService.loadClientByClientId(authRequest.clientId)
            }

/*
            // save the login hint to the session
            // but first check to see if the login hint makes any sense
            val loginHint =
                loginHintExtracter.extractHint(authRequest.extensions[ConnectRequestParameters.LOGIN_HINT])
            if (!loginHint.isNullOrEmpty()) {
                session.setAttribute(ConnectRequestParameters.LOGIN_HINT, loginHint)
            } else {
                session.removeAttribute(ConnectRequestParameters.LOGIN_HINT)
            }
*/

            val prompt = authRequest.extensions[ConnectRequestParameters.PROMPT] as? String?
            if (prompt != null) {
                // we have a "prompt" parameter
                val prompts = prompt.split(ConnectRequestParameters.PROMPT_SEPARATOR)

                if (ConnectRequestParameters.PROMPT_NONE in prompts) {
                    // see if the user's logged in
                    val auth = resolveAuthenticatedUser()

                    if (auth != null) {
                        // user's been logged in already (by session management)
                        // we're OK, continue without prompting
                        return //
//                        chain.doFilter(req, res)
                    } else {
                        logger.info("Client requested no prompt")
                        // user hasn't been logged in, we need to "return an error"
                        val redirectUri = authRequest.redirectUri
                        if (client != null && redirectUri != null) {
                            // if we've got a redirect URI then we'll send it

                            // TODO Stuck to spring/ClientDetails
                            val url = redirectResolver.resolveRedirect(redirectUri, client)

                            try {
                                val uriBuilder = URLBuilder(url)

                                uriBuilder.parameters.append(ConnectRequestParameters.ERROR, ConnectRequestParameters.LOGIN_REQUIRED)
                                val requestState = authRequest.state
                                if (!requestState.isNullOrEmpty()) {
                                    uriBuilder.parameters.append(ConnectRequestParameters.STATE, requestState)
                                }

                                return call.respondRedirect(uriBuilder.build()) // TODO ensure this doesn't continue further
                            } catch (e: URISyntaxException) {
                                logger.error("Can't build redirect URI for prompt=none, sending error instead", e)
                                return call.respond(HttpStatusCode.Forbidden)
                            }
                        }

                        return call.respond(HttpStatusCode.Forbidden)
                    }
                } else if (prompts.contains(ConnectRequestParameters.PROMPT_LOGIN)) {
                    // first see if the user's already been prompted in this session

                    if (true /*session.getAttribute(PROMPTED) == null*/) {
                        // user hasn't been PROMPTED yet, we need to check

//                        session.setAttribute(PROMPT_REQUESTED, true)

                        // see if the user's logged in
                        val auth = resolveAuthenticatedUser()
                        if (auth != null) {
                            // TODO this can not be done in ktor
                            // user's been logged in already (by session management)
                            // log them out and continue
//                            call.authentication
//                            SecurityContextHolder.getContext().authentication = null
                        } else {
                            // user hasn't been logged in yet, we can keep going since we'll get there
                        }
                        return
                    } else {
                        // user has been PROMPTED, we're fine

                        // but first, undo the prompt tag

//                        session.removeAttribute(PROMPTED)
                        return // no interception
//                        chain.doFilter(req, res)
                    }
                } else {
                    // prompt parameter is a value we don't care about, not our business
                    return
//                    chain.doFilter(req, res)
                }
            } else if (authRequest.extensions[ConnectRequestParameters.MAX_AGE] != null ||
                (client?.defaultMaxAge != null)
            ) {
                // default to the client's stored value, check the string parameter

                var max = (client?.defaultMaxAge)
                val maxAge = authRequest.extensions[ConnectRequestParameters.MAX_AGE] as String?
                if (maxAge != null) {
                    max = maxAge.toLong()
                }

                if (max != null) {
//                    val authTime = session.getAttribute(AuthenticationTimeStamper.AUTH_TIMESTAMP) as Date?

/*                  TODO("This belongs in the authorization bit")
                    val now = Date()
                    if (authTime != null) {
                        val seconds = (now.time - authTime.time) / 1000
                        if (seconds > max) {
                            // session is too old, log the user out and continue
                            SecurityContextHolder.getContext().authentication = null
                        }
                    }
*/
                }
            }
        } catch (e: InvalidClientException) {
            // we couldn't find the client, move on and let the rest of the system catch the error
            return
        }
    }


    private fun createRequestMap(parameterMap: Map<String, Array<String>?>): Map<String, String> {
        val requestMap: MutableMap<String, String> = HashMap()
        for ((key, value) in parameterMap) {
            if (!value.isNullOrEmpty()) {
                requestMap[key] = value[0] // add the first value only (which is what Spring seems to do)
            }
        }

        return requestMap
    }

    companion object Plugin: BaseApplicationPlugin<ApplicationCallPipeline, Unit, AuthorizationRequestFilter> {
        /**
         * Logger for this class
         */
        private val logger = getLogger<AuthorizationRequestFilter>()

        const val PROMPTED: String = "PROMPT_FILTER_PROMPTED"
        const val PROMPT_REQUESTED: String = "PROMPT_FILTER_REQUESTED"

        override val key = AttributeKey<AuthorizationRequestFilter>("authorizationRequestFilter")

        override fun install(
            pipeline: ApplicationCallPipeline,
            configure: Unit.() -> Unit,
        ): AuthorizationRequestFilter {
            val plugin = AuthorizationRequestFilter()
            pipeline.receivePipeline.intercept(ApplicationReceivePipeline.Before) { subject ->
                with(plugin) {  doIntercept(subject) }
            }
            return plugin
        }
    }
}
