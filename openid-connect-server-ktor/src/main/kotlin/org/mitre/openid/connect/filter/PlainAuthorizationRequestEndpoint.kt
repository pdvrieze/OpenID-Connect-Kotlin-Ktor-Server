package org.mitre.openid.connect.filter

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.mitre.oauth2.exception.OAuth2Exception
import org.mitre.oauth2.exception.OAuthErrorCodes
import org.mitre.oauth2.model.Authentication
import org.mitre.oauth2.model.OAuth2RequestAuthentication
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.SavedUserAuthentication
import org.mitre.oauth2.model.convert.OAuth2Request
import org.mitre.oauth2.service.ClientLoadingResult
import org.mitre.oauth2.view.respondJson
import org.mitre.openid.connect.request.ConnectRequestParameters
import org.mitre.openid.connect.service.LoginHintExtracter
import org.mitre.openid.connect.service.impl.RemoveLoginHintsWithHTTP
import org.mitre.openid.connect.view.jsonErrorView
import org.mitre.util.getLogger
import org.mitre.web.OpenIdSessionStorage
import org.mitre.web.htmlLoginView
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.authcodeService
import org.mitre.web.util.clientDetailsService
import org.mitre.web.util.openIdContext
import org.mitre.web.util.scopeService
import org.mitre.web.util.update
import java.net.URISyntaxException
import kotlin.collections.component1
import kotlin.collections.component2
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * @author jricher
 */
object PlainAuthorizationRequestEndpoint : KtorEndpoint {
    private val loginHintExtracter: LoginHintExtracter = RemoveLoginHintsWithHTTP()
    override fun Route.addRoutes() {
        authenticate(optional = true) {
            get("authorize") {
                startAuthorizationFlow()
            }
            post("authorize") {
                startAuthorizationFlow()
            }
        }
        post("/token") {
            exchangeAccessToken()
        }
    }

    //    var requestMatcher: RequestMatcher = AntPathRequestMatcher("/authorize")

//    override fun doFilter(req: ServletRequest, res: ServletResponse, chain: FilterChain) {


    private suspend fun RoutingContext.startAuthorizationFlow() {
        val params =
            call.request.queryParameters.let { if (call.request.httpMethod == HttpMethod.Post) it + call.receiveParameters() else it }
        for ((_, values) in params.entries()) {
            // Any repeated parameter is invalid per RFC 6749/ 4.1
            if (values.size != 1) return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST)
        }

        // we have to create our own auth request in order to get at all the parmeters appropriately
        val authRequest: OAuth2Request = openIdContext.authRequestFactory.createAuthorizationRequest(params)
        if (authRequest.clientId.isBlank()) return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST)

        val client = clientDetailsService.loadClientByClientId(authRequest.clientId)
            ?: return jsonErrorView(OAuthErrorCodes.INVALID_CLIENT)

        val auth = openIdContext.resolveAuthenticatedUser(call)
        val state = params["state"]

        // TODO check redirect uri validity (if in the auth request)
        val redirectUri = authRequest.redirectUri ?: client.redirectUris.singleOrNull()
        ?: return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST)

        // save the login hint to the session
        // but first check to see if the login hint makes any sense
        val loginHint =
            loginHintExtracter.extractHint(authRequest.extensions[ConnectRequestParameters.LOGIN_HINT])

//            if (!loginHint.isNullOrEmpty()) {
//                session.setAttribute(ConnectRequestParameters.LOGIN_HINT, loginHint)
//            } else {
//                session.removeAttribute(ConnectRequestParameters.LOGIN_HINT)
//            }

        val prompt = authRequest.extensions[ConnectRequestParameters.PROMPT] as? String?
        if (prompt != null) {
            val cont = promptFlow(prompt, authRequest, client, auth)
            if (!cont) return
        } else {
            val max = authRequest.extensions[ConnectRequestParameters.MAX_AGE]?.let {
                it.toLongOrNull() ?: return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST)
            } ?: client.defaultMaxAge
            if (max != null) {
                // default to the client's stored value, check the string parameter

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

        val responseType = params["response_type"] ?: return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST)



        if (!scopeService.scopesMatch(client.scope?: emptySet(), authRequest.scope)) {
            return jsonErrorView(OAuthErrorCodes.INVALID_SCOPE)
        }
        // TODO check scopes

        if (auth != null) {
            when (responseType) {
                "code" -> return respondWithAuthCode(authRequest, auth, redirectUri, state)
                "token" -> return respondImplicitFlow(responseType, client, authRequest, auth, redirectUri, state)
                else -> return jsonErrorView(OAuthErrorCodes.UNSUPPORTED_GRANT_TYPE)
            }
        }

        call.sessions.update<OpenIdSessionStorage> {
            // not logged in
            OpenIdSessionStorage(authorizationRequest = authRequest, redirectUri = redirectUri, state = state)
        }
        htmlLoginView(loginHint, null, null)
    }


    suspend fun RoutingContext.respondWithAuthCode(
        authRequest: OAuth2Request,
        auth: Authentication,
        effectiveRedirectUri: String,
        state: String?,
    ) {
        val code = authcodeService.createAuthorizationCode(authRequest, auth)
        return call.respondRedirect {
            takeFrom(effectiveRedirectUri)
            parameters.append("code", code)
            if (state != null) parameters.append("state", state)
        }
    }


    suspend fun RoutingContext.respondImplicitFlow(
        responseType: String,
        client: OAuthClientDetails,
        authRequest: OAuth2Request,
        auth: Authentication,
        effectiveRedirectUri: String,
        state: String?,
    ) {
        val granter = openIdContext.tokenGranters[responseType] ?: return jsonErrorView(OAuthErrorCodes.UNSUPPORTED_GRANT_TYPE)
        val r = OAuth2RequestAuthentication(authRequest, SavedUserAuthentication.from(auth))
        val accessToken = granter.getAccessToken(client, r).jwt.serialize()
        return call.respondRedirect {
            takeFrom(effectiveRedirectUri)
            if (state != null) parameters.append("state", state)
            fragment = accessToken
        }
    }

    private suspend fun RoutingContext.promptFlow(
        prompt: String,
        authRequest: OAuth2Request,
        client: OAuthClientDetails?,
        auth: Authentication?,
    ): Boolean {
        TODO("Not correct, not fully implemented")
        // we have a "prompt" parameter
        val prompts = prompt.split(ConnectRequestParameters.PROMPT_SEPARATOR)

        if (ConnectRequestParameters.PROMPT_NONE in prompts) {
            // see if the user's logged in
            if (auth != null) {
                // user's been logged in already (by session management)
                // we're OK, continue without prompting
                return true//
//                        chain.doFilter(req, res)
            }
            logger.info("Client requested no prompt")
            // user hasn't been logged in, we need to "return an error"
            val redirectUri = authRequest.redirectUri
            if (client != null && redirectUri != null) {
                // if we've got a redirect URI then we'll send it

                // TODO Stuck to spring/ClientDetails
                val url = openIdContext.redirectResolver.resolveRedirect(redirectUri, client)

                try {
                    val uriBuilder = URLBuilder(url)

                    uriBuilder.parameters.append(ConnectRequestParameters.ERROR, ConnectRequestParameters.LOGIN_REQUIRED)
                    val requestState = authRequest.state
                    if (!requestState.isNullOrEmpty()) {
                        uriBuilder.parameters.append(ConnectRequestParameters.STATE, requestState)
                    }

                    call.respondRedirect(uriBuilder.build()) // TODO ensure this doesn't continue further
                    return false
                } catch (e: URISyntaxException) {
                    logger.error("Can't build redirect URI for prompt=none, sending error instead", e)
                    jsonErrorView(OAuthErrorCodes.INVALID_REQUEST)
                    return false
                }
            }
            jsonErrorView(OAuthErrorCodes.ACCESS_DENIED)
            return false

        } else if (prompts.contains(ConnectRequestParameters.PROMPT_LOGIN)) {
            // first see if the user's already been prompted in this session

            if (true /*session.getAttribute(PROMPTED) == null*/) {
                // user hasn't been PROMPTED yet, we need to check

//                        session.setAttribute(PROMPT_REQUESTED, true)

                // see if the user's logged in
                val auth = openIdContext.resolveAuthenticatedUser(call)
                if (auth != null) {
                    // TODO this can not be done in ktor
                    // user's been logged in already (by session management)
                    // log them out and continue
//                            call.authentication
//                            SecurityContextHolder.getContext().authentication = null
//                } else {
                    // user hasn't been logged in yet, we can keep going since we'll get there
                }
//            } else {
                // user has been PROMPTED, we're fine but first, undo the prompt tag
                // session.removeAttribute(PROMPTED)
                // no interception
            }
            return true
        }
        // prompt parameter is a value we don't care about, not our business
        return true
    }

    @OptIn(ExperimentalEncodingApi::class)
    private suspend fun RoutingContext.exchangeAccessToken() {

        val postParams = call.receiveParameters()

        if (postParams.entries().any { it.value.size != 1 }) {
            return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST)
        }

        logger.info("Query parameters: ${postParams.entries().joinToString { (k, v) -> "$k=\"${v.single()}\"" }}")

        val grantType = postParams["grant_type"] ?: return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST)
        val code = postParams["code"] ?: return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST)
        val redirectUri = postParams["redirect_uri"] // can be null if also not in original request

        val requestClientId: String? = call.request.queryParameters["client_id"]

        val creds : UserPasswordCredential

        when {
            call.request.authorization() != null -> {
                val authorizationHeader = call.request.parseAuthorizationHeader()
                when (authorizationHeader?.authScheme) {
                    "Basic" -> {
                        creds = call.request.basicAuthenticationCredentials()!!
                    }
                    else -> return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST)
                }

                postParams.getAll("client_id")?.run {
                    if(size > 1) return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST)
                    if (requestClientId!= null && requestClientId != get(0)) {
                        //mismatch between client ids
                        return jsonErrorView(OAuthErrorCodes.INVALID_CLIENT)
                    }
                }

                if (postParams.contains("client_secret")) {
                    // double authorization is not allowed
                    return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST)
                }
            }

            else -> {
                val cid = postParams.getAll("client_id")?.singleOrNull()
                val clientSecret = postParams.getAll("client_secret")?.singleOrNull()
                if (cid == null || clientSecret == null) return jsonErrorView(OAuthErrorCodes.INVALID_CLIENT, HttpStatusCode.Unauthorized)

                creds = UserPasswordCredential(cid, clientSecret)
            }
        }

        val client = when (val c = clientDetailsService.loadClientAuthenticated(creds.name, creds.password)) {
            is ClientLoadingResult.Unauthorized,
            is ClientLoadingResult.Missing -> return jsonErrorView(OAuthErrorCodes.INVALID_CLIENT, HttpStatusCode.Unauthorized)

            is ClientLoadingResult.Found -> c.client
        }


        val req = try {
            authcodeService.consumeAuthorizationCode(code)
        } catch (e: OAuth2Exception) { return jsonErrorView(e.oauth2ErrorCode) }

        // don't allow redirect uri mismatch
        if (req.oAuth2Request.redirectUri != redirectUri) return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST)

        val granter = openIdContext.tokenGranters[grantType]
            ?: return jsonErrorView(OAuthErrorCodes.UNSUPPORTED_GRANT_TYPE)

        val accessToken = granter.getAccessToken(client, req)

        val response = buildJsonObject {
            put("access_token", accessToken.value)
            put("token_type", "Bearer")
            put("expires_in", accessToken.expiresIn)
            accessToken.refreshToken?.let { put("refresh_token", it.value) }
        }

        return call.respondJson(response)
    }


    /**
     * Logger for this class
     */
    private val logger = getLogger()

    const val PROMPTED: String = "PROMPT_FILTER_PROMPTED"
    const val PROMPT_REQUESTED: String = "PROMPT_FILTER_REQUESTED"

    /*
companion object Plugin: BaseApplicationPlugin<ApplicationCallPipeline, Unit, AuthorizationRequestFilter> {

    override val key = AttributeKey<AuthorizationRequestFilter>("AuthorizationRequestFilter")

    override fun install(
        pipeline: ApplicationCallPipeline,
        configure: Unit.() -> Unit,
    ): AuthorizationRequestFilter {
        val plugin = AuthorizationRequestFilter()
        pipeline.intercept(ApplicationCallPipeline.Plugins) {
            with(plugin) {  doIntercept(subject) }
        }

        pipeline.receivePipeline.intercept(ApplicationReceivePipeline.Before) { subject ->
        }
        return plugin
    }
}
*/
}
