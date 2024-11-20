package org.mitre.openid.connect.filter

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import org.mitre.oauth2.exception.InvalidRequestException
import org.mitre.oauth2.exception.OAuth2Exception
import org.mitre.oauth2.exception.OAuthErrorCodes
import org.mitre.oauth2.exception.httpCode
import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.Authentication
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.SavedUserAuthentication
import org.mitre.oauth2.model.request.AuthorizationRequest
import org.mitre.oauth2.model.request.OpenIdAuthorizationRequest
import org.mitre.oauth2.model.request.OpenIdAuthorizationRequest.ResponseMode
import org.mitre.oauth2.service.ClientLoadingResult
import org.mitre.oauth2.token.TokenGranter
import org.mitre.oauth2.view.respondJson
import org.mitre.oauth2.web.OAuthConfirmationController
import org.mitre.openid.connect.request.ConnectRequestParameters
import org.mitre.openid.connect.request.Prompt
import org.mitre.openid.connect.service.LoginHintExtracter
import org.mitre.openid.connect.service.impl.RemoveLoginHintsWithHTTP
import org.mitre.openid.connect.view.OAuthError
import org.mitre.openid.connect.view.jsonErrorView
import org.mitre.util.getLogger
import org.mitre.web.OpenIdSessionStorage
import org.mitre.web.htmlErrorView
import org.mitre.web.htmlLoginView
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.authRequestFactory
import org.mitre.web.util.authcodeService
import org.mitre.web.util.clientDetailsService
import org.mitre.web.util.config
import org.mitre.web.util.openIdContext
import org.mitre.web.util.scopeService
import org.mitre.web.util.userApprovalHandler
import java.net.URISyntaxException
import java.time.Instant
import java.util.*
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
            get("/authorize") { startAuthorizationFlow(call.request.queryParameters) }
            post("/authorize") { // use post parameter user_oauth_approval to distinguish approval from authorize request.
                val postParams = call.receiveParameters()
                if ((postParams.getAll("user_oauth_approval")?.singleOrNull()) == "true") {
                    processApproval(postParams)
                } else {
                    startAuthorizationFlow(call.request.queryParameters + postParams)
                }
            }
//            post("/authorize/approve") { processApproval(call.receiveParameters()) }
        }
        post("/authorize/login") { doLogin() }
        post("/token") {
            try {
                getAccessToken()
            } catch (e: OAuth2Exception) {
                logger.info("Token endpoint error", e)
                call.response.cacheControl(CacheControl.NoStore(null))
                call.response.header(HttpHeaders.Pragma, "no-cache")
                jsonErrorView(e.oauth2ErrorCode)
            }
        }
    }

    private fun RoutingContext.toMap(params: Parameters): Map<String, String> {
        try {
            return params.entries().associate { (k, v) -> k to v.single() }
        } catch (e: Exception) {
            throw InvalidRequestException("Duplicate parameters")
        }
    }

    //    var requestMatcher: RequestMatcher = AntPathRequestMatcher("/authorize")

//    override fun doFilter(req: ServletRequest, res: ServletResponse, chain: FilterChain) {

    private suspend fun RoutingContext.startAuthorizationFlow(rawParams: Parameters) {
        val params = toMap(rawParams)

        // we have to create our own auth request in order to get at all the parmeters appropriately
        val authRequest: AuthorizationRequest = openIdContext.authRequestFactory.createAuthorizationRequest(params)
        if (authRequest.clientId.isBlank()) return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST)

        val client = clientDetailsService.loadClientByClientId(authRequest.clientId)
            ?: return jsonErrorView(OAuthErrorCodes.INVALID_CLIENT)

        var auth = openIdContext.resolveAuthenticatedUser(call)
        val state = params["state"]

        // TODO check redirect uri validity (if in the auth request)
        val redirectUri = authRequest.redirectUri ?: client.redirectUris.singleOrNull()
        ?: return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST)

        // save the login hint to the session
        // but first check to see if the login hint makes any sense
        val loginHint =
            loginHintExtracter.extractHint((authRequest as? OpenIdAuthorizationRequest)?.loginHint)

        val responseType = (params["response_type"] ?: return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST))
            .normalizeResponseType()

        val hasSession: Boolean
        var pendingSession = when (val s = call.sessions.get<OpenIdSessionStorage>()) {
            null -> {
                hasSession = false
                OpenIdSessionStorage(loginHint = loginHint, responseType = responseType, authTime = null)
            }
            else -> {
                hasSession = false
                s.copy(loginHint = loginHint, responseType = responseType)
            }
        }

        val prompts = when {
            pendingSession.pendingPrompts != null -> pendingSession.pendingPrompts
            else -> (authRequest as? OpenIdAuthorizationRequest)?.prompts//.extensions[ConnectRequestParameters.PROMPT]?.let { Prompt.parseSet(it) }
        }
        if (prompts != null) {
            pendingSession = promptFlow(prompts, authRequest, client, auth, pendingSession) ?: return
        } else {
            val max = (authRequest as? OpenIdAuthorizationRequest)?.maxAge ?: client.defaultMaxAge
            val authTime = pendingSession.authTime
            if (max != null && authTime != null) {
                // default to the client's stored value, check the string parameter

                val now = Instant.now()
                if(now.isAfter(authTime.plusSeconds(max))) {
                    pendingSession = pendingSession.copy(principal = null, authTime = null)
                    auth = null
                }
            }
        }

        if (!scopeService.scopesMatch(client.scope?: emptySet(), authRequest.scope)) {
            return jsonErrorView(OAuthErrorCodes.INVALID_SCOPE)
        }
        // TODO check scopes

        if (auth != null) { // If we are still authenticated
            val approvedAuthRequest = when {
                userApprovalHandler.isApproved(authRequest, auth, params) -> {
                    if (!hasSession) return call.response.status(HttpStatusCode.Forbidden) // CSRF error
                    userApprovalHandler.updateAfterApproval(authRequest, auth, params)
                }

                else -> userApprovalHandler.checkForPreApproval(authRequest, auth)
            }

            when {
                !approvedAuthRequest.isApproved -> {
                    call.sessions.set(pendingSession.copy(authorizationRequest = authRequest, redirectUri = redirectUri, state = state))
                    return respondWithApprovalRequest(approvedAuthRequest, auth, prompts, client, redirectUri)
                }

                responseType.isAuthCodeFlow -> return respondWithAuthCode(approvedAuthRequest, auth, redirectUri, state)

                responseType.isImplicitFlow -> return respondImplicitFlow(responseType, client, approvedAuthRequest, auth, redirectUri, state, params)

                responseType.isHybridFlow -> return respondHybridFlow(responseType, client, approvedAuthRequest, auth, redirectUri, state)

                else -> return jsonErrorView(OAuthErrorCodes.UNSUPPORTED_GRANT_TYPE)
            }
        }

        call.sessions.set(pendingSession.copy(authorizationRequest = authRequest, redirectUri = redirectUri, state = state))

        htmlLoginView(config.issuerUrl("authorize/login"), loginHint, null, null, status = HttpStatusCode.Unauthorized)
    }


    suspend fun RoutingContext.respondWithAuthCode(
        authRequest: AuthorizationRequest,
        auth: Authentication,
        effectiveRedirectUri: String,
        state: String?,
    ) {
        val code = authcodeService.createAuthorizationCode(authRequest, auth)
        return call.respondRedirect {
            takeFrom(effectiveRedirectUri)
            when {
                authRequest is OpenIdAuthorizationRequest && authRequest.responseMode == ResponseMode.FRAGMENT ->
                    fragment = code

                else -> parameters.append("code", code)
            }
            if (state != null) parameters.append("state", state)
        }
    }


    suspend fun RoutingContext.respondImplicitFlow(
        responseType: NormalizedResponseType,
        client: OAuthClientDetails,
        authRequest: AuthorizationRequest,
        auth: Authentication,
        effectiveRedirectUri: String,
        state: String?,
        requestParameters: Map<String, String>,
    ) {
        val r = AuthenticatedAuthorizationRequest(authRequest, SavedUserAuthentication.from(auth))
        val accessToken = if(responseType.token) {
            val granter = getGranter("token") ?: return jsonErrorView(OAuthErrorCodes.UNSUPPORTED_GRANT_TYPE)

            granter.getAccessToken(client, r, requestParameters = requestParameters).jwt.serialize()
        } else null

        val idToken = if(responseType.idToken) {
            val granter = getGranter("id_token") ?: return jsonErrorView(OAuthErrorCodes.UNSUPPORTED_GRANT_TYPE)
            granter.getAccessToken(client, r, requestParameters = requestParameters,).jwt.serialize() // should use separate function using DefaultOIDCTokenService
        } else null

        call.response.cacheControl(CacheControl.NoStore(null))
        call.response.header(HttpHeaders.Pragma, "no-cache")
        return call.respondRedirect {
            takeFrom(effectiveRedirectUri)

            val p = when {
                authRequest is OpenIdAuthorizationRequest && authRequest.responseMode == ResponseMode.QUERY -> parameters
                else -> ParametersBuilder()
            }

            if (state != null) p.append("state", state)
            if (accessToken != null) p.append("access_token", accessToken)
            p.append("token_type", "Bearer")
            if (idToken != null) p.append("id_token", idToken)
            if (r.authorizationRequest.scope.isNotEmpty()) p.append("scope", r.authorizationRequest.scope.joinToString(" "))

            if(p != parameters) {
                fragment = p.entries().joinToString("&") { (k, v) -> "${k.encodeURLParameter()}=${v.single().encodeURLParameter()}"}
            }
        }
    }

    suspend fun RoutingContext.respondHybridFlow(
        responseType: NormalizedResponseType,
        client: OAuthClientDetails,
        authRequest: AuthorizationRequest,
        auth: Authentication,
        effectiveRedirectUri: String,
        state: String?,
    ) {
        val code = authcodeService.createAuthorizationCode(authRequest, auth)

        return call.respondRedirect {
            takeFrom(effectiveRedirectUri)
            val p = when {
                authRequest is OpenIdAuthorizationRequest && authRequest.responseMode == ResponseMode.FRAGMENT -> ParametersBuilder()
                else -> parameters
            }

            p.append("code", code)
            if (state != null) p.append("state", state)

            if(p != parameters) {
                fragment = p.entries().joinToString("&") { (k, v) -> "${k.encodeURLParameter()}=${v.single().encodeURLParameter()}"}
            }
        }
    }

    private suspend fun RoutingContext.respondWithApprovalRequest(
        authRequest: AuthorizationRequest,
        auth: Authentication,
        prompts: Set<Prompt>?,
        client: OAuthClientDetails,
        redirectUri: String?,
    ) {
        with (OAuthConfirmationController) { confirmAccess(auth, authRequest, prompts ?: emptySet(), client, redirectUri) }
    }

    private suspend fun RoutingContext.promptFlow(
        prompts: Set<Prompt>,
        authRequest: AuthorizationRequest,
        client: OAuthClientDetails,
        auth: Authentication?,
        pendingSession: OpenIdSessionStorage,
    ): OpenIdSessionStorage? {
        @Suppress("NAME_SHADOWING")
        var pendingSession = pendingSession
        // we have a "prompt" parameter

        if (Prompt.NONE in prompts) {
            if (prompts.size != 1) {
                jsonErrorView(OAuthErrorCodes.INVALID_REQUEST)
                return null
            }
            if (auth != null) {
                // user's been logged in already (with regular ktor auth - eg. sessions)
                // we're OK, continue without prompting
                return pendingSession.copy(pendingPrompts = null)
            }
            logger.info("Client requested no prompt")
            // user hasn't been logged in, we need to "return an error"
            val redirectUri = authRequest.redirectUri
            if (redirectUri != null) {
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

                    call.sessions.set(pendingSession)
                    call.respondRedirect(uriBuilder.build()) // TODO ensure this doesn't continue further
                    return null
                } catch (e: URISyntaxException) {
                    call.sessions.set(pendingSession)
                    logger.error("Can't build redirect URI for prompt=none, sending error instead", e)
                    jsonErrorView(OAuthErrorCodes.INVALID_REQUEST)
                    return null
                }
            }
            jsonErrorView(OAuthErrorCodes.ACCESS_DENIED)
            return null
        }

        // select account is not quite supported by the UI/system
        if (Prompt.LOGIN in prompts || Prompt.SELECT_ACCOUNT in prompts) {
            // first see if the user's already been prompted in this session
            return pendingSession.copy(principal = null, authTime = null) // this
        }

        if (auth != null && Prompt.CONSENT in prompts) {
            call.sessions.set(pendingSession)
            respondWithApprovalRequest(authRequest, auth, prompts, client, authRequest.redirectUri)
//            call.respondRedirect("/oauth/confirm_access")
            return null
        }
        // prompt parameter is a value we don't care about, not our business
        return pendingSession
    }

    suspend fun RoutingContext.doLogin() {
        val formParams = call.receiveParameters()

        val userName = formParams["username"]
        val password = formParams["password"]

        if (!userName.isNullOrBlank() && !password.isNullOrBlank() &&
            openIdContext.checkCredential(UserPasswordCredential(userName, password))) {

            val principal = UserIdPrincipal(userName)
            val oldSession = call.sessions.get<OpenIdSessionStorage>() ?:
                return htmlErrorView(OAuthErrorCodes.INVALID_REQUEST, "Missing session")

            val prompts = oldSession.pendingPrompts?.let { it.filterTo(HashSet()) { it !in arrayOf(Prompt.LOGIN, Prompt.SELECT_ACCOUNT) } }

            val authRequest = oldSession.authorizationRequest
                ?: return htmlErrorView(OAuthErrorCodes.INVALID_REQUEST, "Missing authorization request", HttpStatusCode.BadRequest)

            val auth = openIdContext.principalToAuthentication(principal)
                ?: return htmlErrorView(OAuthErrorCodes.SERVER_ERROR, "Invalid user")

            val client = clientDetailsService.loadClientByClientId(authRequest.clientId)
                ?: return htmlErrorView(OAuthErrorCodes.SERVER_ERROR, "Missing client")

            val paramMap = toMap(formParams)
            val approvedAuthRequest = when {
                Prompt.CONSENT !in (oldSession.pendingPrompts ?: emptySet()) &&
                        userApprovalHandler.isApproved(authRequest, auth, paramMap) ->
                    userApprovalHandler.updateAfterApproval(authRequest, auth, paramMap)

                else -> userApprovalHandler.checkForPreApproval(authRequest, auth)
            }



            if (!approvedAuthRequest.isApproved) {

                call.sessions.set(oldSession.copy(principal = principal, authTime = Instant.now()))
                respondWithApprovalRequest(authRequest, auth, prompts, client, authRequest.redirectUri)
//            call.respondRedirect("/oauth/confirm_access")
                return

            } else {
                call.sessions.set(oldSession.copy(principal = principal, authTime = Instant.now()))
                with(PlainAuthorizationRequestEndpoint) {
                    val redirect = oldSession.redirectUri ?: return jsonErrorView(OAuthErrorCodes.SERVER_ERROR)

                    return respondWithAuthCode(approvedAuthRequest, auth, redirect, oldSession.state)
                }
            }
            /*
                        val approvedAuthRequest = when {
                userApprovalHandler.isApproved(authRequest, auth) -> {
                    if (!hasSession) return call.response.status(HttpStatusCode.Forbidden) // CSRF error
                    userApprovalHandler.updateAfterApproval(authRequest, auth)
                }

                else -> userApprovalHandler.checkForPreApproval(authRequest, auth, prompts)
            }

             */
        }

        val locales = call.request.acceptLanguageItems().map { Locale(it.value) }
        val error = openIdContext.messageSource.resolveCode("login.error", locales)?.format(null)

        return htmlLoginView(config.issuerUrl("authorize/login"), formParams["username"], error, formParams["redirect"], HttpStatusCode.Unauthorized)
    }

    private suspend fun RoutingContext.processApproval(rawParams: Parameters) {
        if (! call.queryParameters.isEmpty()) {
            return htmlErrorView(OAuthErrorCodes.INVALID_REQUEST, "Unexpected query parameters")
        }

        val params = toMap(rawParams)

        if (params["user_oauth_approval"] != "true") {
            return htmlErrorView(OAuthErrorCodes.INVALID_REQUEST, "Missing form data")
        }
        val oldSession = call.sessions.get<OpenIdSessionStorage>() ?: return htmlErrorView(OAuthErrorCodes.INVALID_REQUEST, "Missing session")
        val authRequest = oldSession.authorizationRequest ?: return htmlErrorView(OAuthErrorCodes.INVALID_REQUEST, "Missing authorization request")

        val pendingSession = oldSession.copy(pendingPrompts = null)

        val principal = oldSession.principal ?: return htmlErrorView(OAuthErrorCodes.INVALID_REQUEST, "Missing user")

        val auth = openIdContext.principalToAuthentication(principal)
            ?: return htmlErrorView(OAuthErrorCodes.SERVER_ERROR, "Invalid user")

        val approvedAuthRequest = when {
            userApprovalHandler.isApproved(authRequest, auth, params) -> {
                userApprovalHandler.updateAfterApproval(authRequest, auth, params)
            }

            else -> authRequest
        }

        val redirectUri = oldSession.redirectUri!!

        val client = clientDetailsService.loadClientByClientId(authRequest.clientId)
            ?: return htmlErrorView(OAuthErrorCodes.SERVER_ERROR, "Missing client")

        val responseType = oldSession.responseType!!
        val state = oldSession.state

        when {
            !approvedAuthRequest.isApproved -> { // TODO respond with error
                call.sessions.set(pendingSession.copy(authorizationRequest = authRequest, redirectUri = redirectUri, state = state))
                return respondWithApprovalRequest(approvedAuthRequest, auth, null, client, redirectUri)
            }

            responseType.isAuthCodeFlow -> return respondWithAuthCode(approvedAuthRequest, auth, redirectUri, state)

            responseType.isImplicitFlow -> return respondImplicitFlow(responseType, client, approvedAuthRequest, auth, redirectUri, state, params)

            responseType.isHybridFlow -> return respondHybridFlow(responseType, client, approvedAuthRequest, auth, redirectUri, state)

            else -> return jsonErrorView(OAuthErrorCodes.UNSUPPORTED_GRANT_TYPE)
        }


    }

    private fun RoutingContext.getGranter(grantType: String): TokenGranter? {
        return openIdContext.tokenGranters[grantType]
    }

    fun RoutingContext.getAuthenticatedClient(postParams: Map<String, String>): ClientLoadingResult {
        val requestClientId: String? = call.request.queryParameters["client_id"]

        val creds : UserPasswordCredential

        when {
            call.request.authorization() != null -> {
                val authorizationHeader = call.request.parseAuthorizationHeader()
                when (authorizationHeader?.authScheme) {
                    "Basic" -> {
                        creds = call.request.basicAuthenticationCredentials()!!
                    }
                    else -> return ClientLoadingResult(OAuthErrorCodes.INVALID_REQUEST)
                }

                postParams.get("client_id")?.let { postClientId ->
                    if (requestClientId!= null && requestClientId != postClientId) {
                        //mismatch between client ids
                        return ClientLoadingResult(OAuthErrorCodes.INVALID_CLIENT)
                    }
                }

                if (postParams.contains("client_secret")) {
                    // double authorization is not allowed
                    return ClientLoadingResult(OAuthErrorCodes.INVALID_REQUEST)
                }
            }

            else -> {
                val cid = postParams["client_id"]
                val clientSecret = postParams["client_secret"]
                if (cid == null || clientSecret == null) return ClientLoadingResult(OAuthErrorCodes.INVALID_CLIENT, HttpStatusCode.Unauthorized.value)

                creds = UserPasswordCredential(cid, clientSecret)
            }
        }

        return clientDetailsService.loadClientAuthenticated(creds.name, creds.password)
    }

    @OptIn(ExperimentalEncodingApi::class)
    private suspend fun RoutingContext.getAccessToken() {

        val postParams = runCatching { call.receiveParameters().entries().associate { (k, v) -> k to v.single() } }
            .onFailure { return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST, it.message) }
            .getOrThrow()

        logger.info("Query parameters: ${postParams.entries.joinToString { (k, v) -> "$k=\"$v\"" }}")

        val grantType = (postParams["grant_type"] ?: return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST))

        val granter = getGranter(grantType)
            ?: return jsonErrorView(OAuthErrorCodes.UNSUPPORTED_GRANT_TYPE)

        val client = when (val c = getAuthenticatedClient(postParams)) {
            is ClientLoadingResult.Unauthorized,
            is ClientLoadingResult.Missing -> return jsonErrorView(OAuthErrorCodes.INVALID_CLIENT, HttpStatusCode.Unauthorized)
            is ClientLoadingResult.Error -> return jsonErrorView(c.errorCode, c.status?.let{HttpStatusCode.fromValue(it) } ?: c.errorCode.httpCode ?: HttpStatusCode.BadRequest)

            is ClientLoadingResult.Found -> c.client
        }

        val accessToken = try {
                granter.grant(grantType, authRequestFactory.createAuthorizationRequest(postParams, client), client, postParams)
        } catch (e: OAuth2Exception) {
            return call.respondJson(OAuthError(e.oauth2ErrorCode, e.message), e.oauth2ErrorCode.httpCode ?: HttpStatusCode.BadRequest)
        }

        val response = AuthTokenResponse (
            accessToken.value,
            "Bearer",
            accessToken.expiresIn,
            accessToken.refreshToken?.value
        )

        call.response.cacheControl(CacheControl.NoStore(null))
        call.response.header(HttpHeaders.Pragma, "no-cache")
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

/**
 * Converts response types to lowercase (it is case-insensitive) and sort it (multi-value is order independent)
 */
private fun String.normalizeResponseType(): NormalizedResponseType {
    var token = false
    var idToken = false
    var code = false
    for (type in splitToSequence(' ')) {
        when (type) {
            "token" -> token = true
            "id_token" -> idToken = true
            "code" -> code = true
        }
    }
    return NormalizedResponseType(code, token, idToken)
}

@Serializable(ResponseTypeSerializer::class)
data class NormalizedResponseType(val code: Boolean, val token: Boolean, val idToken: Boolean) {
    val isAuthCodeFlow get() = code && !(idToken || token)
    val isImplicitFlow get() = !code && (idToken || token)
    val isHybridFlow get() = code && (idToken || token)

    override fun toString(): String = buildList<String> {
        if (code) add("code")
        if (idToken) add("id_token")
        if(token) add("token")
    }.joinToString(" ")
}

internal class ResponseTypeSerializer : KSerializer<NormalizedResponseType> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("ResponseType", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: NormalizedResponseType) {
        encoder.encodeString(value.toString())
    }

    override fun deserialize(decoder: Decoder): NormalizedResponseType {
        return decoder.decodeString().normalizeResponseType()
    }
}

@Serializable
data class AuthTokenResponse(
    @SerialName("access_token")
    val accessToken: String,
    val tokenType: String,
    val expiresIn: Int? = null,
    val refreshToken: String? = null,
)
