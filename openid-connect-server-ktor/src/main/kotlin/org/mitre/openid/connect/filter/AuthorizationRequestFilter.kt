package org.mitre.openid.connect.filter

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.util.*
import io.ktor.util.pipeline.*
import org.mitre.oauth2.exception.InvalidClientException
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.openid.connect.request.ConnectRequestParameters
import org.mitre.openid.connect.web.AuthenticationTimeStamper
import org.mitre.util.getLogger
import org.mitre.web.util.openIdContext
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
//    private val loginHintExtracter: LoginHintExtracter = RemoveLoginHintsWithHTTP()

//    var requestMatcher: RequestMatcher = AntPathRequestMatcher("/authorize")

//    override fun doFilter(req: ServletRequest, res: ServletResponse, chain: FilterChain) {
    private fun PipelineContext<Any, ApplicationCall>.doIntercept(subject: Any) {
        // skip everything that's not an authorize URL
        if (!call.request.path().startsWith("/authorize")) return // skip intercept


        try {
            // we have to create our own auth request in order to get at all the parmeters appropriately
            val authRequest: AuthorizationRequest?

            var client: OAuthClientDetails? = null

            authRequest = openIdContext.authRequestFactory
                .createAuthorizationRequest()

            if (!authRequest.clientId.isNullOrEmpty()) {
                client = clientService.loadClientByClientId(authRequest.clientId)
            }

            // save the login hint to the session
            // but first check to see if the login hint makes any sense
            val loginHint =
                loginHintExtracter.extractHint(authRequest.extensions[ConnectRequestParameters.LOGIN_HINT] as String?)
            if (!loginHint.isNullOrEmpty()) {
                session.setAttribute(ConnectRequestParameters.LOGIN_HINT, loginHint)
            } else {
                session.removeAttribute(ConnectRequestParameters.LOGIN_HINT)
            }

            val prompt = authRequest.extensions[ConnectRequestParameters.PROMPT] as? String?
            if (prompt != null) {
                // we have a "prompt" parameter
                val prompts = prompt.split(ConnectRequestParameters.PROMPT_SEPARATOR)

                if (ConnectRequestParameters.PROMPT_NONE in prompts) {
                    // see if the user's logged in
                    val auth = SecurityContextHolder.getContext().authentication

                    if (auth != null) {
                        // user's been logged in already (by session management)
                        // we're OK, continue without prompting
                        chain.doFilter(req, res)
                    } else {
                        Companion.logger.info("Client requested no prompt")
                        // user hasn't been logged in, we need to "return an error"
                        if (client != null && authRequest.redirectUri != null) {
                            // if we've got a redirect URI then we'll send it

                            // TODO Stuck to spring/ClientDetails
                            val url = redirectResolver.resolveRedirect(authRequest.redirectUri, client as ClientDetails)

                            try {
                                val uriBuilder = URIBuilder(url)

                                uriBuilder.addParameter(ConnectRequestParameters.ERROR, ConnectRequestParameters.LOGIN_REQUIRED)
                                if (!authRequest.state.isNullOrEmpty()) {
                                    uriBuilder.addParameter(ConnectRequestParameters.STATE, authRequest.state) // copy the state parameter if one was given
                                }

                                response.sendRedirect(uriBuilder.toString())
                                return
                            } catch (e: URISyntaxException) {
                                Companion.logger.error("Can't build redirect URI for prompt=none, sending error instead", e)
                                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied")
                                return
                            }
                        }

                        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied")
                        return
                    }
                } else if (prompts.contains(ConnectRequestParameters.PROMPT_LOGIN)) {
                    // first see if the user's already been prompted in this session

                    if (session.getAttribute(PROMPTED) == null) {
                        // user hasn't been PROMPTED yet, we need to check

                        session.setAttribute(PROMPT_REQUESTED, true)

                        // see if the user's logged in
                        val auth = SecurityContextHolder.getContext().authentication
                        if (auth != null) {
                            // user's been logged in already (by session management)
                            // log them out and continue
                            SecurityContextHolder.getContext().authentication = null
                            chain.doFilter(req, res)
                        } else {
                            // user hasn't been logged in yet, we can keep going since we'll get there
                            chain.doFilter(req, res)
                        }
                    } else {
                        // user has been PROMPTED, we're fine

                        // but first, undo the prompt tag

                        session.removeAttribute(PROMPTED)
                        chain.doFilter(req, res)
                    }
                } else {
                    // prompt parameter is a value we don't care about, not our business
                    chain.doFilter(req, res)
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
                    val authTime = session.getAttribute(AuthenticationTimeStamper.AUTH_TIMESTAMP) as Date?

                    val now = Date()
                    if (authTime != null) {
                        val seconds = (now.time - authTime.time) / 1000
                        if (seconds > max) {
                            // session is too old, log the user out and continue
                            SecurityContextHolder.getContext().authentication = null
                        }
                    }
                }
                chain.doFilter(req, res)
            } else {
                // no prompt parameter, not our business
                chain.doFilter(req, res)
            }
        } catch (e: InvalidClientException) {
            // we couldn't find the client, move on and let the rest of the system catch the error
            chain.doFilter(req, res)
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
