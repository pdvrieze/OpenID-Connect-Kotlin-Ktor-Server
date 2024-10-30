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
import org.mitre.oauth2.exception.OAuthErrorCodes
import org.mitre.oauth2.exception.httpCode
import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.Authentication
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.SavedUserAuthentication
import org.mitre.oauth2.model.convert.AuthorizationRequest
import org.mitre.oauth2.service.ClientLoadingResult
import org.mitre.oauth2.token.TokenGranter
import org.mitre.oauth2.view.respondJson
import org.mitre.openid.connect.request.ConnectRequestParameters
import org.mitre.openid.connect.request.ConnectRequestParameters.PROMPT_CONSENT
import org.mitre.openid.connect.request.ConnectRequestParameters.PROMPT_LOGIN
import org.mitre.openid.connect.request.ConnectRequestParameters.PROMPT_SELECT_ACCOUNT
import org.mitre.openid.connect.service.LoginHintExtracter
import org.mitre.openid.connect.service.impl.RemoveLoginHintsWithHTTP
import org.mitre.openid.connect.view.jsonErrorView
import org.mitre.util.getLogger
import org.mitre.web.OpenIdSessionStorage
import org.mitre.web.htmlLoginView
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.authRequestFactory
import org.mitre.web.util.authcodeService
import org.mitre.web.util.clientDetailsService
import org.mitre.web.util.openIdContext
import org.mitre.web.util.scopeService
import java.net.URISyntaxException
import java.time.Instant
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
            get("authorize") { startAuthorizationFlow(call.request.queryParameters) }
            post("authorize") {
                startAuthorizationFlow(call.request.queryParameters + call.receiveParameters())
            }
        }
        post("/token") {
            getAccessToken()
        }
    }

    //    var requestMatcher: RequestMatcher = AntPathRequestMatcher("/authorize")

//    override fun doFilter(req: ServletRequest, res: ServletResponse, chain: FilterChain) {

    private suspend fun RoutingContext.startAuthorizationFlow(params: Parameters) {
        for ((_, values) in params.entries()) {
            // Any repeated parameter is invalid per RFC 6749/ 4.1
            if (values.size != 1) return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST)
        }

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
            loginHintExtracter.extractHint(authRequest.extensions[ConnectRequestParameters.LOGIN_HINT])

        val responseType = (params["response_type"] ?: return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST))
            .normalizeResponseType()

        var pendingSession = call.sessions.get<OpenIdSessionStorage>()?.copy(loginHint = loginHint, responseType = responseType)
            ?: OpenIdSessionStorage(loginHint = loginHint, responseType = responseType, authTime = null)

        val prompts = when {
            pendingSession.pendingPrompts != null -> pendingSession.pendingPrompts
            else -> authRequest.extensions[ConnectRequestParameters.PROMPT]?.splitToSequence(' ')?.toHashSet()
        }
        if (prompts != null) {
            pendingSession = promptFlow(prompts, authRequest, client, auth, pendingSession) ?: return
        } else {
            val max = authRequest.extensions[ConnectRequestParameters.MAX_AGE]?.let {
                it.toLongOrNull() ?: return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST)
            } ?: client.defaultMaxAge
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
            when {
                responseType.isAuthCodeFlow -> return respondWithAuthCode(authRequest, auth, redirectUri, state)

                responseType.isImplicitFlow -> return respondImplicitFlow(responseType, client, authRequest, auth, redirectUri, state)

                responseType.isHybridFlow -> return respondHybridFlow(responseType, client, authRequest, auth, redirectUri, state)

                else -> return jsonErrorView(OAuthErrorCodes.UNSUPPORTED_GRANT_TYPE)
            }
        }

        call.sessions.set(pendingSession.copy(authorizationRequest = authRequest, redirectUri = redirectUri, state = state))

        htmlLoginView(loginHint, null, null)
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
                authRequest.isOpenId && authRequest.requestParameters["response_mode"] == "fragment" ->
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
    ) {
        val r = AuthenticatedAuthorizationRequest(authRequest, SavedUserAuthentication.from(auth))
        val accessToken = if(responseType.token) {
            val granter = getGranter("token") ?: return jsonErrorView(OAuthErrorCodes.UNSUPPORTED_GRANT_TYPE)

            granter.getAccessToken(client, r).jwt.serialize()
        } else null

        val idToken = if(responseType.idToken) {
            val granter = getGranter("id_token") ?: return jsonErrorView(OAuthErrorCodes.UNSUPPORTED_GRANT_TYPE)
            granter.getAccessToken(client, r,).jwt.serialize() // should use separate function using DefaultOIDCTokenService
        } else null

        return call.respondRedirect {
            takeFrom(effectiveRedirectUri)

            val p = when {
                authRequest.isOpenId && authRequest.requestParameters["response_mode"] == "query" -> parameters
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
                authRequest.isOpenId && authRequest.requestParameters["response_mode"] == "fragment" -> ParametersBuilder()
                else -> parameters
            }

            p.append("code", code)
            if (state != null) p.append("state", state)

            if(p != parameters) {
                fragment = p.entries().joinToString("&") { (k, v) -> "${k.encodeURLParameter()}=${v.single().encodeURLParameter()}"}
            }
        }
    }

    private suspend fun RoutingContext.promptFlow(
        prompts: Set<String>,
        authRequest: AuthorizationRequest,
        client: OAuthClientDetails?,
        auth: Authentication?,
        pendingSession: OpenIdSessionStorage,
    ): OpenIdSessionStorage? {
        @Suppress("NAME_SHADOWING")
        var pendingSession = pendingSession
        // we have a "prompt" parameter

        if (ConnectRequestParameters.PROMPT_NONE in prompts) {
            if (prompts.size!=1) {
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
        if (PROMPT_LOGIN in prompts || PROMPT_SELECT_ACCOUNT in prompts) {
            // first see if the user's already been prompted in this session
            return pendingSession.copy(principal = null, authTime = null) // this
        }

        if (PROMPT_CONSENT in prompts) {
            call.sessions.set(pendingSession)
            call.respondRedirect("/oauth/confirm_access")
            return null
        }
        // prompt parameter is a value we don't care about, not our business
        return pendingSession
    }

    private fun RoutingContext.getGranter(grantType: String): TokenGranter? {
        return openIdContext.tokenGranters[grantType]
    }

    fun RoutingContext.getAuthenticatedClient(postParams: Parameters): ClientLoadingResult {
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

                postParams.getAll("client_id")?.run {
                    if(size > 1) return ClientLoadingResult(OAuthErrorCodes.INVALID_REQUEST)
                    if (requestClientId!= null && requestClientId != get(0)) {
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
                val cid = postParams.getAll("client_id")?.singleOrNull()
                val clientSecret = postParams.getAll("client_secret")?.singleOrNull()
                if (cid == null || clientSecret == null) return ClientLoadingResult(OAuthErrorCodes.INVALID_CLIENT, HttpStatusCode.Unauthorized.value)

                creds = UserPasswordCredential(cid, clientSecret)
            }
        }

        return clientDetailsService.loadClientAuthenticated(creds.name, creds.password)
    }

    @OptIn(ExperimentalEncodingApi::class)
    private suspend fun RoutingContext.getAccessToken() {

        val postParams = call.receiveParameters()

        if (postParams.entries().any { it.value.size != 1 }) {
            return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST)
        }

        logger.info("Query parameters: ${postParams.entries().joinToString { (k, v) -> "$k=\"${v.single()}\"" }}")

        val grantType = (postParams["grant_type"] ?: return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST))

        val granter = getGranter(grantType)
            ?: return jsonErrorView(OAuthErrorCodes.UNSUPPORTED_GRANT_TYPE)

        val client = when (val c = getAuthenticatedClient(postParams)) {
            is ClientLoadingResult.Unauthorized,
            is ClientLoadingResult.Missing -> return jsonErrorView(OAuthErrorCodes.INVALID_CLIENT, HttpStatusCode.Unauthorized)
            is ClientLoadingResult.Error -> return jsonErrorView(c.errorCode, c.status?.let{HttpStatusCode.fromValue(it) } ?: c.errorCode.httpCode ?: HttpStatusCode.BadRequest)

            is ClientLoadingResult.Found -> c.client
        }

        val accessToken = granter.grant(grantType, authRequestFactory.createAuthorizationRequest(postParams, client), client)

        val response = AuthTokenResponse (
            accessToken.value,
            "Bearer",
            accessToken.expiresIn,
            accessToken.refreshToken?.value
        )

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

internal class ResponseTypeSerializer() : KSerializer<NormalizedResponseType> {
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
