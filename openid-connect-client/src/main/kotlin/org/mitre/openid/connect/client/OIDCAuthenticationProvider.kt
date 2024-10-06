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
package org.mitre.openid.connect.client

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.util.Base64
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.jwt.SignedJWT
import io.ktor.client.*
import io.ktor.client.engine.*
import io.ktor.client.engine.cio.*
import io.ktor.client.engine.java.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.sessions.*
import io.ktor.server.util.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import org.mitre.jose.keystore.JWKSetKeyStore
import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService
import org.mitre.jwt.signer.service.JWKSetCacheService
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.jwt.signer.service.impl.DefaultJWTSigningAndValidationService
import org.mitre.jwt.signer.service.impl.SymmetricKeyJWTValidatorCacheService
import org.mitre.oauth2.exception.AuthenticationException
import org.mitre.oauth2.model.OAuthClientDetails.AuthMethod
import org.mitre.oauth2.model.PKCEAlgorithm
import org.mitre.openid.connect.client.service.AuthRequestOptionsService
import org.mitre.openid.connect.client.service.AuthRequestUrlBuilder
import org.mitre.openid.connect.client.service.ClientConfigurationService
import org.mitre.openid.connect.client.service.IssuerService
import org.mitre.openid.connect.client.service.ServerConfigurationService
import org.mitre.openid.connect.client.service.getIssuer
import org.mitre.openid.connect.client.service.impl.StaticAuthRequestOptionsService
import org.mitre.openid.connect.model.OIDCAuthenticationToken
import org.mitre.openid.connect.model.PendingOIDCAuthenticationToken
import org.mitre.util.asString
import org.mitre.util.getLogger
import java.io.IOException
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.text.ParseException
import java.util.*

typealias  AuthenticationServiceException=AuthenticationException

/**
 * OpenID Connect Authentication Filter class
 *
 * @author nemonik, jricher
 */
class OIDCAuthenticationProvider internal constructor(config: Config) : AuthenticationProvider(config) {
    //
    // Getters and setters for configuration variables
    //
    // Allow for time sync issues by having a window of X seconds.
    var timeSkewAllowance: Int = config.timeSkewAllowance

    // fetches and caches public keys for servers
    val validationServices: JWKSetCacheService = config.validationServices ?: SimpleValidationService()

    // creates JWT signer/validators for symmetric keys
    val symmetricCacheService: SymmetricKeyJWTValidatorCacheService = config.symmetricCacheService

    // signer based on keypair for this client (for outgoing auth requests)
    private val authenticationSignerService: JWTSigningAndValidationService? = config.authenticationSignerService

    //    private var httpClient: HttpClient? = null
    private val httpClient = HttpClient(Java)

    /*
	 * Modular services to build out client filter.
	 */
    // looks at the request and determines which issuer to use for lookup on the server
//    lateinit var issuerService: IssuerService
    private val issuerService = config.issuerService

    // holds server information (auth URI, token URI, etc.), indexed by issuer
    val serverConfigurationService: ServerConfigurationService = config.serverConfigurationService

    // holds client information (client ID, redirect URI, etc.), indexed by issuer of the server
    val clientConfigurationService: ClientConfigurationService = config.clientConfigurationService

    // provides extra options to inject into the outbound request
    val authRequestOptionsService: AuthRequestOptionsService =
        config.authRequestOptionsService // initialize with an empty set of options

    // builds the actual request URI based on input from all other services
    lateinit var authRequestUrlBuilder: AuthRequestUrlBuilder

    // private helpers to handle target link URLs
    var targetLinkURIAuthenticationSuccessHandler: TargetLinkURIAuthenticationSuccessHandler =
        TargetLinkURIAuthenticationSuccessHandler()
    private var deepLinkFilter: TargetLinkURIChecker? = null

    protected var httpSocketTimeout: Int = HTTP_SOCKET_TIMEOUT

//    private val authenticator = OIDCAuthenticationProvider2()
    private var userInfoFetcher = UserInfoFetcher()

    private var authoritiesMapper: OIDCAuthoritiesMapper = NamedAdminAuthoritiesMapper()


    inner class SimpleValidationService(
    ) : JWKSetCacheService {
        lateinit var jwksUri: String
        lateinit var service: JWTSigningAndValidationService

        override suspend fun getValidator(jwksUri: String): JWTSigningAndValidationService? {
            if (::jwksUri.isInitialized) {
                require(this.jwksUri == jwksUri) { "Differing jwksUri's" }
                return service
            }
            require(!::jwksUri.isInitialized || jwksUri == jwksUri) { "Differing jwksUri's" }



//            val request = HttpGet(jwksUri)
            val response = httpClient.request(jwksUri)
            if (! response.status.isSuccess()) {
                return null
            }
            val keyStore = JWKSetKeyStore(JWKSet.parse(response.bodyAsText()))

            service = DefaultJWTSigningAndValidationService(keyStore)
            this.jwksUri = jwksUri // delay setting this until no more options for exceptions

            return service
        }

        override suspend fun getEncrypter(jwksUri: String): JWTEncryptionAndDecryptionService? {
            return null
        }
    }


    /*
         * This is the main entry point for the filter.
         *
         * (non-Javadoc)
         *
         * @see org.springframework.security.web.authentication.
         * AbstractAuthenticationProcessingFilter
         * #attemptAuthentication(javax.servlet.http.HttpServletRequest,
         * javax.servlet.http.HttpServletResponse)
         */
    override suspend fun onAuthenticate(context: AuthenticationContext) {
//    override fun attemptAuthentication(request: HttpServletRequest, response: HttpServletResponse): Authentication? {
        val call = context.call
        val paramError = call.request.queryParameters["error"]
        val paramCode = call.request.queryParameters["code"]

        when {
            !paramError.isNullOrEmpty() -> {
                // there's an error coming back from the server, need to handle this

                handleError(context)
                return // no auth, response is sent to display page or something
            }

            !paramCode.isNullOrEmpty() -> {
                // we got back the code, need to process this to get our tokens

                val auth = handleAuthorizationCodeResponse(context, paramCode)

                // TODO authenticate somehow
                return
            }

            else -> {
                // not an error, not a code, must be an initial login of some type

                handleAuthorizationRequest(context)

                return // no auth, response redirected to the server's Auth Endpoint (or possibly to the account chooser)
            }
        }
    }

    /**
     * Initiate an Authorization request
     *
     * The request from which to extract parameters and perform the
     * authentication
     * @throws IOException
     * If an input or output exception occurs
     */
    protected suspend fun handleAuthorizationRequest(context: AuthenticationContext) {
        val call = context.call

        val issResp = issuerService.getIssuer(call.request)

        if (issResp == null) {
            logger.error("Null issuer response returned from service.")
            throw AuthenticationException("No issuer found.")
        }

        if (issResp.shouldRedirect()) {
            call.respondRedirect(issResp.redirectUrl!!)
        } else {
            val issuer = issResp.issuer

            if (!issResp.targetLinkUri.isNullOrEmpty()) {
                // there's a target URL in the response, we should save this so we can forward to it later
                call.sessions.set(ClientSession(target=issResp.targetLinkUri))
            }

            if (issuer.isNullOrEmpty()) {
                logger.error("No issuer found: $issuer")
                throw AuthenticationException("No issuer found: $issuer")
            }

            val serverConfig = serverConfigurationService.getServerConfiguration(issuer)
            if (serverConfig == null) {
                logger.error("No server configuration found for issuer: $issuer")
                throw AuthenticationException("No server configuration found for issuer: $issuer")
            }

            val clientConfig = clientConfigurationService.getClientConfiguration(serverConfig)
            if (clientConfig == null) {
                logger.error("No client configuration found for issuer: $issuer")
                throw AuthenticationException("No client configuration found for issuer: $issuer")
            }

            val clientRegisteredRedirectUri = clientConfig.registeredRedirectUri
            val redirectUri: String = clientRegisteredRedirectUri?.singleOrNull() ?: call.request.uri

            // this value comes back in the id token and is checked there
            val nonce = createNonce()

            // this value comes back in the auth code response
            val state = createState()

            val options: MutableMap<String, String> =
                authRequestOptionsService.getOptions(serverConfig, clientConfig, call.request)

            var codeVerifier: String? = null
            // if we're using PKCE, handle the challenge here
            val codeChallengeMethod = clientConfig.codeChallengeMethod
            if (codeChallengeMethod != null) {
                options["code_challenge_method"] = codeChallengeMethod.name

                codeVerifier = createCodeVerifier()
                if (codeChallengeMethod == PKCEAlgorithm.plain) {
                    options["code_challenge"] = codeVerifier

                } else if (codeChallengeMethod == PKCEAlgorithm.S256) {
                    try {
                        val digest = MessageDigest.getInstance("SHA-256")
                        val hash = Base64URL.encode(digest.digest(codeVerifier.toByteArray(StandardCharsets.US_ASCII)))
                            .toString()
                        options["code_challenge"] = hash
                    } catch (e: NoSuchAlgorithmException) {
                        // TODO Auto-generated catch block
                        e.printStackTrace()
                    }
                }
            }

            val authRequest =
                authRequestUrlBuilder.buildAuthRequestUrl(serverConfig, clientConfig, redirectUri, nonce, state, options, issResp.loginHint)

            logger.debug("Auth Request:  $authRequest")

            val session = call.sessions.get<ClientSession>()
            val newSession = session?.copy(
                issuer = serverConfig.issuer,
                redirectUri = redirectUri,
                state = state,
                nonce = nonce,
                codeVerifier = codeVerifier
            ) ?: ClientSession(issuer = serverConfig.issuer, redirectUri = redirectUri, state = state, nonce = nonce, codeVerifier = codeVerifier)
            call.sessions.set(newSession)

            call.respondRedirect(authRequest)
        }
    }

    /**
     * The request from which to extract parameters and perform the
     * authentication
     * @return The authenticated user token, or null if authentication is
     * incomplete.
     */
    protected suspend fun handleAuthorizationCodeResponse(
        context: AuthenticationContext,
        authorizationCode: String,
    ): OIDCAuthenticationToken {
        val call = context.call
        val request = call.request

//        val session = request.session
        val session = call.sessions.get<ClientSession>()

        // check for state, if it doesn't match we bail early
        val storedState = session?.state
        val requestState = request.queryParameters["state"]
        if (storedState == null || storedState != requestState) {
            throw AuthenticationException("State parameter mismatch on return. Expected $storedState got $requestState")
        }

        // look up the issuer that we set out to talk to
        val issuer = session.issuer
            ?: throw AuthenticationException("Issuer unexpectedly not stored in session")

        // pull the configurations based on that issuer
        val serverConfig = serverConfigurationService.getServerConfiguration(issuer)!!
        val clientConfig = clientConfigurationService.getClientConfiguration(serverConfig)


        val form = ParametersBuilder()

//        val form: MultiValueMap<String, String?> = LinkedMultiValueMap()
        form.append("grant_type", "authorization_code")
        form.append("code", authorizationCode)
        for ((k, v) in authRequestOptionsService.getTokenOptions(serverConfig, clientConfig!!, request)) {
            form.append(k, v)
        }

        session.codeVerifier?.let { form.append("code_verifier", it) }

        session.redirectUri?.let { form.append("redirect_uri", it) }


        val rb = HttpRequestBuilder(serverConfig.tokenEndpointUri)
        rb.timeout { socketTimeoutMillis = httpSocketTimeout.toLong() }


        if (AuthMethod.SECRET_BASIC == clientConfig.tokenEndpointAuthMethod) {
            val f = String.format(
                "Basic %s", Base64.encode(
                    String.format(
                        "%s:%s",
                        url { appendEncodedPathSegments(clientConfig.clientId!!) },
                        url { appendEncodedPathSegments(clientConfig.clientSecret!!) }
                    )
                )
            )

            rb.header(HttpHeaders.Authorization, f)

            // use BASIC auth if configured to do so
        } else {
            // we're not doing basic auth, figure out what other flavor we have

            if (AuthMethod.SECRET_JWT == clientConfig.tokenEndpointAuthMethod || AuthMethod.PRIVATE_KEY == clientConfig.tokenEndpointAuthMethod) {
                // do a symmetric secret signed JWT for auth


                var alg = clientConfig.tokenEndpointAuthSigningAlg

                val signer: JWTSigningAndValidationService?
                when {
                    AuthMethod.SECRET_JWT == clientConfig.tokenEndpointAuthMethod &&
                            (JWSAlgorithm.HS256 == alg || JWSAlgorithm.HS384 == alg || JWSAlgorithm.HS512 == alg) -> {
                        // generate one based on client secret

                        signer = symmetricCacheService.getSymmetricValidator(clientConfig.client)
                    }

                    AuthMethod.PRIVATE_KEY == clientConfig.tokenEndpointAuthMethod -> {
                        // needs to be wired in to the bean

                        signer = authenticationSignerService

                        if (alg == null) {
                            alg = authenticationSignerService!!.defaultSigningAlgorithm
                        }
                    }

                    else -> throw AuthenticationException("Couldn't find required signer service for use with private key auth.")
                }

                if (signer == null) {
                    throw AuthenticationException("Couldn't find required signer service for use with private key auth.")
                }

                val claimsSet = JWTClaimsSet.Builder()

                claimsSet.issuer(clientConfig.clientId)
                claimsSet.subject(clientConfig.clientId)
                claimsSet.audience(listOf(serverConfig.tokenEndpointUri))
                claimsSet.jwtID(UUID.randomUUID().toString())

                // TODO: make this configurable
                val exp = Date(System.currentTimeMillis() + (60 * 1000)) // auth good for 60 seconds
                claimsSet.expirationTime(exp)

                val now = Date(System.currentTimeMillis())
                claimsSet.issueTime(now)
                claimsSet.notBeforeTime(now)

                val header = JWSHeader(
                    alg, null, null, null, null, null, null, null, null, null,
                    signer.defaultSignerKeyId,
                    null, null
                )
                val jwt = SignedJWT(header, claimsSet.build())

                signer.signJwt(jwt, alg!!)

                form.append("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                form.append("client_assertion", jwt.serialize())
            } else {
                //Alternatively use form based auth
                form.append("client_id", clientConfig.clientId!!)
                form.append("client_secret", clientConfig.clientSecret!!)
            }
        }

        logger.debug("tokenEndpointURI = " + serverConfig.tokenEndpointUri)
        logger.debug("form = $form")

        var jsonString: String? = null

        val result = httpClient.post(rb)
        if (!result.status.isSuccess()) {
            logger.error("Endpoint error: ${result.status.value} ${result.status.description}")
            throw AuthenticationException("Endpoint error: ${result.status.value} ${result.status.description}")
        }
        jsonString = result.bodyAsText()

        logger.debug("from TokenEndpoint jsonString = $jsonString")

        val tokenResponse = Json.parseToJsonElement(jsonString)
        if (tokenResponse !is JsonObject) {
            throw AuthenticationException("Token Endpoint did not return a JSON object: $tokenResponse")
        }

        val error = tokenResponse["error"]
        if (error != null) {
            // Handle error
            logger.error("Token Endpoint returned: $error")

            throw AuthenticationException("Unable to obtain Access Token.  Token Endpoint returned: $error")
        }

        // Extract the id_token to insert into the
        // OIDCAuthenticationToken

        // get out all the token strings


        val accessTokenValue = tokenResponse["access_token"]?.asString()
            ?: throw AuthenticationException("Token Endpoint did not return an access_token: $jsonString")

        val idTokenValue = tokenResponse["id_token"]?.asString()
            ?: throw AuthenticationException("Token Endpoint did not return an id_token")

        val refreshTokenValue = tokenResponse["refresh_token"]?.asString()

        try {
            val idToken = JWTParser.parse(idTokenValue)

            // validate our ID Token over a number of tests
            val idClaims = idToken.jwtClaimsSet

            // check the signature
            var jwtValidator: JWTSigningAndValidationService? = null

            val tokenAlg = idToken.header.algorithm

            val clientAlg: Algorithm? = clientConfig.idTokenSignedResponseAlg

            if (clientAlg != null) {
                if (clientAlg != tokenAlg) {
                    throw AuthenticationException("Token algorithm $tokenAlg does not match expected algorithm $clientAlg")
                }
            }

            if (idToken is PlainJWT) {
                if (clientAlg == null) {
                    throw AuthenticationException("Unsigned ID tokens can only be used if explicitly configured in client.")
                }

                if (tokenAlg != null && tokenAlg != Algorithm.NONE) {
                    throw AuthenticationException("Unsigned token received, expected signature with $tokenAlg")
                }
            } else if (idToken is SignedJWT) {
                jwtValidator =
                    if (tokenAlg == JWSAlgorithm.HS256 || tokenAlg == JWSAlgorithm.HS384 || tokenAlg == JWSAlgorithm.HS512) {
                        // generate one based on client secret

                        symmetricCacheService.getSymmetricValidator(clientConfig.client)
                    } else {
                        // otherwise load from the server's public key
                        validationServices.getValidator(serverConfig.jwksUri)
                    }

                if (jwtValidator != null) {
                    if (!jwtValidator.validateSignature(idToken)) {
                        throw AuthenticationException("Signature validation failed")
                    }
                } else {
                    logger.error("No validation service found. Skipping signature validation")
                    throw AuthenticationException("Unable to find an appropriate signature validator for ID Token.")
                }
            } // TODO: encrypted id tokens


            // check the issuer
            if (idClaims.issuer == null) {
                throw AuthenticationException("Id Token Issuer is null")
            } else if (idClaims.issuer != serverConfig.issuer) {
                throw AuthenticationException("Issuers do not match, expected " + serverConfig.issuer + " got " + idClaims.issuer)
            }

            // check expiration
            if (idClaims.expirationTime == null) {
                throw AuthenticationException("Id Token does not have required expiration claim")
            } else {
                // it's not null, see if it's expired
                val now = Date(System.currentTimeMillis() - (timeSkewAllowance * 1000))
                if (now.after(idClaims.expirationTime)) {
                    throw AuthenticationException("Id Token is expired: " + idClaims.expirationTime)
                }
            }

            // check not before
            if (idClaims.notBeforeTime != null) {
                val now = Date(System.currentTimeMillis() + (timeSkewAllowance * 1000))
                if (now.before(idClaims.notBeforeTime)) {
                    throw AuthenticationException("Id Token not valid untill: " + idClaims.notBeforeTime)
                }
            }

            // check issued at
            if (idClaims.issueTime == null) {
                throw AuthenticationException("Id Token does not have required issued-at claim")
            } else {
                // since it's not null, see if it was issued in the future
                val now = Date(System.currentTimeMillis() + (timeSkewAllowance * 1000))
                if (now.before(idClaims.issueTime)) {
                    throw AuthenticationException("Id Token was issued in the future: " + idClaims.issueTime)
                }
            }

            // check audience
            if (idClaims.audience == null) {
                throw AuthenticationException("Id token audience is null")
            } else if (!idClaims.audience.contains(clientConfig.clientId)) {
                throw AuthenticationException("Audience does not match, expected " + clientConfig.clientId + " got " + idClaims.audience)
            }

            // compare the nonce to our stored claim
            val nonce = idClaims.getStringClaim("nonce")
            if (nonce.isNullOrEmpty()) {
                logger.error("ID token did not contain a nonce claim.")

                throw AuthenticationException("ID token did not contain a nonce claim.")
            }

            val storedNonce = session.nonce
            if (nonce != storedNonce) {
                logger.error(
                    "Possible replay attack detected! The comparison of the nonce in the returned ID Token " +
                            "to the session $NONCE_SESSION_VARIABLE failed. Expected $storedNonce got $nonce."
                )

                throw AuthenticationException("Possible replay attack detected! The comparison of the nonce in the returned ID Token to the session $NONCE_SESSION_VARIABLE failed. Expected $storedNonce got $nonce.")
            }

            // construct an PendingOIDCAuthenticationToken and return a Authentication object w/the userId and the idToken
            val token = PendingOIDCAuthenticationToken(
                idClaims.subject, idClaims.issuer,
                serverConfig,
                idToken, accessTokenValue, refreshTokenValue!!
            )

            return authenticate(token)
        } catch (e: ParseException) {
            throw AuthenticationException("Couldn't parse idToken: ", e)
        }
    }


    private suspend fun authenticate(authentication: PendingOIDCAuthenticationToken): OIDCAuthenticationToken {

        // get the ID Token value out
        val idToken = authentication.idToken

        // load the user info if we can
        val userInfo = userInfoFetcher.loadUserInfo(authentication)

        if (userInfo == null) {
            // user info not found -- could be an error, could be fine
        } else {
            // if we found userinfo, double check it
            if (!userInfo.subject.isNullOrEmpty() && userInfo.subject != authentication.sub) {
                // the userinfo came back and the user_id fields don't match what was in the id_token
                throw AuthenticationException("user_id mismatch between id_token and user_info call: " + authentication.sub + " / " + userInfo.subject)
            }
        }

        return OIDCAuthenticationToken(
            sub = authentication.sub,
            issuer = authentication.issuer,
            userInfo = userInfo,
            authorities = authoritiesMapper.mapAuthorities(idToken!!, userInfo),
            idToken = authentication.idToken,
            accessTokenValue = authentication.accessTokenValue,
            refreshTokenValue = authentication.refreshTokenValue
        )
    }

    /**
     * Handle Authorization Endpoint error
     *
     * The request from which to extract parameters and handle the
     * error
     * The response, needed to do a redirect to display the error
     * @throws IOException
     * If an input or output exception occurs
     */
    @Throws(IOException::class)
    protected fun handleError(context: AuthenticationContext) {
        val request = context.call.request
        val error = request.queryParameters["error"]!!
        val errorDescription = request.queryParameters["error_description"]
        val errorURI = request.queryParameters["error_uri"]

        throw AuthorizationEndpointException(error, errorDescription, errorURI)
    }

//    fun setAuthenticationSuccessHandler(successHandler: AuthenticationSuccessHandler) {
//        targetLinkURIAuthenticationSuccessHandler.passthrough = successHandler
//    }


    /**
     * Handle a successful authentication event. If the issuer service sets
     * a target URL, we'll go to that. Otherwise we'll let the superclass handle
     * it for us with the configured behavior.
     */
    inner class TargetLinkURIAuthenticationSuccessHandler {
        var passthrough: Nothing? /*AuthenticationSuccessHandler?*/ = null

        suspend fun onAuthenticationSuccess(
            authenticationContext: AuthenticationContext,
            authentication: Authentication,
        ) {
            val session = authenticationContext.call.sessions.get<ClientSession>()

            // check to see if we've got a target
            var target = session?.target

            if (!target.isNullOrEmpty()) {
                if (session!=null) {
                    authenticationContext.call.sessions.set(session.copy(target = null))
                }

                if (deepLinkFilter != null) {
                    target = deepLinkFilter!!.filter(target)
                }
                authenticationContext.call.respondRedirect(target!!)
            }
            // if the target was blank, use the default behavior here
        }
    }


    fun targetLinkURIChecker(): TargetLinkURIChecker? {
        return deepLinkFilter
    }

    fun setTargetLinkURIChecker(deepLinkFilter: TargetLinkURIChecker?) {
        this.deepLinkFilter = deepLinkFilter
    }

    companion object {
        protected const val REDIRECT_URI_SESION_VARIABLE: String = "redirect_uri"
        protected const val CODE_VERIFIER_SESSION_VARIABLE: String = "code_verifier"
        protected const val STATE_SESSION_VARIABLE: String = "state"
        protected const val NONCE_SESSION_VARIABLE: String = "nonce"
        protected const val ISSUER_SESSION_VARIABLE: String = "issuer"
        protected const val TARGET_SESSION_VARIABLE: String = "target"
        protected const val HTTP_SOCKET_TIMEOUT: Int = 30000

        const val FILTER_PROCESSES_URL: String = "/openid_connect_login"

        private val logger = getLogger<OIDCAuthenticationProvider>()

        /**
         * Create a cryptographically random nonce and store it in the session
         */
        protected fun createNonce(): String {
            return BigInteger(50, SecureRandom()).toString(16)
        }

        /**
         * Create a cryptographically random state and store it in the session
         */
        protected fun createState(): String {
            return BigInteger(50, SecureRandom()).toString(16)
        }

        /**
         * Create a random code challenge and store it in the session
         */
        protected fun createCodeVerifier(): String {
            return BigInteger(50, SecureRandom()).toString(16)
        }

    }

    class Config(
        name: String? = null,
    ) : AuthenticationProvider.Config(name) {
        lateinit var authenticationSignerService: JWTSigningAndValidationService
        lateinit var clientConfigurationService: ClientConfigurationService
        lateinit var serverConfigurationService: ServerConfigurationService
        lateinit var issuerService: IssuerService // TODO instantiate default
        var symmetricCacheService: SymmetricKeyJWTValidatorCacheService = SymmetricKeyJWTValidatorCacheService()
        var validationServices: JWKSetCacheService? = null
        var timeSkewAllowance: Int = 300
        var authRequestOptionsService: AuthRequestOptionsService = StaticAuthRequestOptionsService()

        internal fun build() = OIDCAuthenticationProvider(this)
    }
}

fun AuthenticationConfig.openIDC(name: String? = null, configure: OIDCAuthenticationProvider.Config.() -> Unit) {
    val provider = OIDCAuthenticationProvider.Config().apply(configure).build()
    register(provider)
}

@Serializable
data class ClientSession(
    val target: String? = null,
    val issuer: String? = null,
    val redirectUri: String? = null,
    val state: String? = null,
    val nonce: String? = null,
    val codeVerifier: String? = null,
) {
}
