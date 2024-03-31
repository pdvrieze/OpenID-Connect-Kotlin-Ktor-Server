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

import com.google.common.collect.Lists
import com.google.gson.JsonParser
import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.Base64
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.jwt.SignedJWT
import org.apache.http.client.HttpClient
import org.apache.http.client.config.RequestConfig
import org.apache.http.impl.client.HttpClientBuilder
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.jwt.signer.service.impl.JWKSetCacheService
import org.mitre.jwt.signer.service.impl.SymmetricKeyJWTValidatorCacheService
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod
import org.mitre.oauth2.model.PKCEAlgorithm
import org.mitre.openid.connect.client.service.AuthRequestOptionsService
import org.mitre.openid.connect.client.service.AuthRequestUrlBuilder
import org.mitre.openid.connect.client.service.ClientConfigurationService
import org.mitre.openid.connect.client.service.IssuerService
import org.mitre.openid.connect.client.service.ServerConfigurationService
import org.mitre.openid.connect.client.service.impl.StaticAuthRequestOptionsService
import org.mitre.openid.connect.model.PendingOIDCAuthenticationToken
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpMethod
import org.springframework.http.client.ClientHttpRequest
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory
import org.springframework.security.authentication.AuthenticationServiceException
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.stereotype.Component
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import org.springframework.web.client.RestClientException
import org.springframework.web.client.RestTemplate
import org.springframework.web.util.UriUtils
import java.io.IOException
import java.math.BigInteger
import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.text.ParseException
import java.util.*
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpSession

/**
 * OpenID Connect Authentication Filter class
 *
 * @author nemonik, jricher
 */
@Component
class OIDCAuthenticationFilter : AbstractAuthenticationProcessingFilter(FILTER_PROCESSES_URL) {
    //
    // Getters and setters for configuration variables
    //
    // Allow for time sync issues by having a window of X seconds.
    var timeSkewAllowance: Int = 300

    // fetches and caches public keys for servers
    @Autowired(required = false)
    var validationServices: JWKSetCacheService? = null

    // creates JWT signer/validators for symmetric keys
    @Autowired(required = false)
    var symmetricCacheService: SymmetricKeyJWTValidatorCacheService? = null

    // signer based on keypair for this client (for outgoing auth requests)
    @Autowired(required = false)
    private val authenticationSignerService: JWTSigningAndValidationService? = null

    @Autowired(required = false)
    private var httpClient: HttpClient? = null

    /*
	 * Modular services to build out client filter.
	 */
    // looks at the request and determines which issuer to use for lookup on the server
    lateinit var issuerService: IssuerService

    // holds server information (auth URI, token URI, etc.), indexed by issuer
    var serverConfigurationService: ServerConfigurationService? = null

    // holds client information (client ID, redirect URI, etc.), indexed by issuer of the server
    var clientConfigurationService: ClientConfigurationService? = null

    // provides extra options to inject into the outbound request
    var authRequestOptionsService: AuthRequestOptionsService =
        StaticAuthRequestOptionsService() // initialize with an empty set of options

    // builds the actual request URI based on input from all other services
    lateinit var authRequestUrlBuilder: AuthRequestUrlBuilder

    // private helpers to handle target link URLs
    var targetLinkURIAuthenticationSuccessHandler: TargetLinkURIAuthenticationSuccessHandler =
        TargetLinkURIAuthenticationSuccessHandler()
    private var deepLinkFilter: TargetLinkURIChecker? = null

    protected var httpSocketTimeout: Int = HTTP_SOCKET_TIMEOUT

    /**
     * OpenIdConnectAuthenticationFilter constructor
     */
    init {
        targetLinkURIAuthenticationSuccessHandler.passthrough = super.getSuccessHandler()
        super.setAuthenticationSuccessHandler(targetLinkURIAuthenticationSuccessHandler)
    }

    override fun afterPropertiesSet() {
        super.afterPropertiesSet()

        // if our JOSE validators don't get wired in, drop defaults into place
        if (validationServices == null) {
            validationServices = JWKSetCacheService()
        }

        if (symmetricCacheService == null) {
            symmetricCacheService = SymmetricKeyJWTValidatorCacheService()
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
    @Throws(AuthenticationException::class, IOException::class, ServletException::class)
    override fun attemptAuthentication(request: HttpServletRequest, response: HttpServletResponse): Authentication? {
        if (!request.getParameter("error").isNullOrEmpty()) {
            // there's an error coming back from the server, need to handle this

            handleError(request, response)
            return null // no auth, response is sent to display page or something
        } else if (!request.getParameter("code").isNullOrEmpty()) {
            // we got back the code, need to process this to get our tokens

            val auth = handleAuthorizationCodeResponse(request, response)
            return auth
        } else {
            // not an error, not a code, must be an initial login of some type

            handleAuthorizationRequest(request, response)

            return null // no auth, response redirected to the server's Auth Endpoint (or possibly to the account chooser)
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
    @Throws(IOException::class)
    protected fun handleAuthorizationRequest(request: HttpServletRequest, response: HttpServletResponse) {
        val session = request.session

        val issResp = issuerService.getIssuer(request)

        if (issResp == null) {
            logger.error("Null issuer response returned from service.")
            throw AuthenticationServiceException("No issuer found.")
        }

        if (issResp.shouldRedirect()) {
            response.sendRedirect(issResp.redirectUrl)
        } else {
            val issuer = issResp.issuer

            if (!issResp.targetLinkUri.isNullOrEmpty()) {
                // there's a target URL in the response, we should save this so we can forward to it later
                session.setAttribute(TARGET_SESSION_VARIABLE, issResp.targetLinkUri)
            }

            if (issuer.isNullOrEmpty()) {
                logger.error("No issuer found: $issuer")
                throw AuthenticationServiceException("No issuer found: $issuer")
            }

            val serverConfig = serverConfigurationService!!.getServerConfiguration(issuer)
            if (serverConfig == null) {
                logger.error("No server configuration found for issuer: $issuer")
                throw AuthenticationServiceException("No server configuration found for issuer: $issuer")
            }


            session.setAttribute(ISSUER_SESSION_VARIABLE, serverConfig.issuer)

            val clientConfig = clientConfigurationService!!.getClientConfiguration(serverConfig)
            if (clientConfig == null) {
                logger.error("No client configuration found for issuer: $issuer")
                throw AuthenticationServiceException("No client configuration found for issuer: $issuer")
            }

            val redirectUri: String?
            val clientRegisteredRedirectUri = clientConfig.registeredRedirectUri
            redirectUri =
                if (clientRegisteredRedirectUri != null && clientRegisteredRedirectUri.size == 1) {
                    // if there's a redirect uri configured (and only one), use that
                    clientRegisteredRedirectUri.single()
                } else {
                    // otherwise our redirect URI is this current URL, with no query parameters
                    request.requestURL.toString()
                }
            session.setAttribute(REDIRECT_URI_SESION_VARIABLE, redirectUri)

            // this value comes back in the id token and is checked there
            val nonce = createNonce(session)

            // this value comes back in the auth code response
            val state = createState(session)

            val options: MutableMap<String, String> =
                authRequestOptionsService.getOptions(serverConfig, clientConfig, request)

            // if we're using PKCE, handle the challenge here
            if (clientConfig.codeChallengeMethod != null) {
                val codeVerifier = createCodeVerifier(session)
                options.put("code_challenge_method", clientConfig.codeChallengeMethod!!.name)
                if (clientConfig.codeChallengeMethod == PKCEAlgorithm.plain) {
                    options.put("code_challenge", codeVerifier)
                } else if (clientConfig.codeChallengeMethod == PKCEAlgorithm.S256) {
                    try {
                        val digest = MessageDigest.getInstance("SHA-256")
                        val hash = Base64URL.encode(digest.digest(codeVerifier.toByteArray(StandardCharsets.US_ASCII)))
                            .toString()
                        options.put("code_challenge", hash)
                    } catch (e: NoSuchAlgorithmException) {
                        // TODO Auto-generated catch block
                        e.printStackTrace()
                    }
                }
            }

            val authRequest =
                authRequestUrlBuilder.buildAuthRequestUrl(serverConfig, clientConfig, redirectUri, nonce, state, options, issResp.loginHint)

            logger.debug("Auth Request:  $authRequest")

            response.sendRedirect(authRequest)
        }
    }

    /**
     * The request from which to extract parameters and perform the
     * authentication
     * @return The authenticated user token, or null if authentication is
     * incomplete.
     */
    protected fun handleAuthorizationCodeResponse(
        request: HttpServletRequest,
        response: HttpServletResponse?
    ): Authentication {
        val authorizationCode = request.getParameter("code")

        val session = request.session

        // check for state, if it doesn't match we bail early
        val storedState = getStoredState(session)
        val requestState = request.getParameter("state")
        if (storedState == null || storedState != requestState) {
            throw AuthenticationServiceException("State parameter mismatch on return. Expected $storedState got $requestState")
        }

        // look up the issuer that we set out to talk to
        val issuer = getStoredSessionString(session, ISSUER_SESSION_VARIABLE)
            ?: throw AuthenticationServiceException("Issuer unexpectedly not stored in session")

        // pull the configurations based on that issuer
        val serverConfig = serverConfigurationService!!.getServerConfiguration(issuer)!!
        val clientConfig = clientConfigurationService!!.getClientConfiguration(serverConfig)

        val form: MultiValueMap<String, String?> = LinkedMultiValueMap()
        form.add("grant_type", "authorization_code")
        form.add("code", authorizationCode)
        form.setAll(authRequestOptionsService.getTokenOptions(serverConfig!!, clientConfig!!, request))

        val codeVerifier = getStoredCodeVerifier(session)
        if (codeVerifier != null) {
            form.add("code_verifier", codeVerifier)
        }

        val redirectUri = getStoredSessionString(session, REDIRECT_URI_SESION_VARIABLE)
        if (redirectUri != null) {
            form.add("redirect_uri", redirectUri)
        }

        // Handle Token Endpoint interaction
        val httpClient: HttpClient = this.httpClient ?: run {
            HttpClientBuilder.create()
                .useSystemProperties()
                .setDefaultRequestConfig(
                    RequestConfig.custom()
                        .setSocketTimeout(httpSocketTimeout)
                        .build()
                )
                .build().also { this.httpClient = it }
        }

        val factory = HttpComponentsClientHttpRequestFactory(httpClient)

        val restTemplate: RestTemplate

        if (AuthMethod.SECRET_BASIC == clientConfig.tokenEndpointAuthMethod) {
            // use BASIC auth if configured to do so
            restTemplate = object : RestTemplate(factory) {
                @Throws(IOException::class)
                override fun createRequest(url: URI, method: HttpMethod): ClientHttpRequest {
                    val httpRequest = super.createRequest(url, method)
                    httpRequest.headers.add(
                        "Authorization",
                        String.format(
                            "Basic %s", Base64.encode(
                                String.format(
                                    "%s:%s",
                                    UriUtils.encodePathSegment(clientConfig.clientId, "UTF-8"),
                                    UriUtils.encodePathSegment(clientConfig.clientSecret, "UTF-8")
                                )
                            )
                        )
                    )

                    return httpRequest
                }
            }
        } else {
            // we're not doing basic auth, figure out what other flavor we have
            restTemplate = RestTemplate(factory)

            if (AuthMethod.SECRET_JWT == clientConfig.tokenEndpointAuthMethod || AuthMethod.PRIVATE_KEY == clientConfig.tokenEndpointAuthMethod) {
                // do a symmetric secret signed JWT for auth


                var signer: JWTSigningAndValidationService? = null
                var alg = clientConfig.tokenEndpointAuthSigningAlg

                if (AuthMethod.SECRET_JWT == clientConfig.tokenEndpointAuthMethod &&
                    (JWSAlgorithm.HS256 == alg || JWSAlgorithm.HS384 == alg || JWSAlgorithm.HS512 == alg)
                ) {
                    // generate one based on client secret

                    signer = symmetricCacheService!!.getSymmetricValidtor(clientConfig.client)
                } else if (AuthMethod.PRIVATE_KEY == clientConfig.tokenEndpointAuthMethod) {
                    // needs to be wired in to the bean

                    signer = authenticationSignerService

                    if (alg == null) {
                        alg = authenticationSignerService!!.defaultSigningAlgorithm
                    }
                }

                if (signer == null) {
                    throw AuthenticationServiceException("Couldn't find required signer service for use with private key auth.")
                }

                val claimsSet = JWTClaimsSet.Builder()

                claimsSet.issuer(clientConfig.clientId)
                claimsSet.subject(clientConfig.clientId)
                claimsSet.audience(Lists.newArrayList(serverConfig.tokenEndpointUri))
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

                form.add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                form.add("client_assertion", jwt.serialize())
            } else {
                //Alternatively use form based auth
                form.add("client_id", clientConfig.clientId)
                form.add("client_secret", clientConfig.clientSecret)
            }
        }

        logger.debug("tokenEndpointURI = " + serverConfig.tokenEndpointUri)
        logger.debug("form = $form")

        var jsonString: String? = null

        try {
            jsonString = restTemplate.postForObject(serverConfig.tokenEndpointUri, form, String::class.java)
        } catch (e: RestClientException) {
            // Handle error

            logger.error("Token Endpoint error response:  " + e.message)

            throw AuthenticationServiceException("Unable to obtain Access Token: " + e.message)
        }

        logger.debug("from TokenEndpoint jsonString = $jsonString")

        val jsonRoot = JsonParser().parse(jsonString)
        if (!jsonRoot.isJsonObject) {
            throw AuthenticationServiceException("Token Endpoint did not return a JSON object: $jsonRoot")
        }

        val tokenResponse = jsonRoot.asJsonObject

        if (tokenResponse["error"] != null) {
            // Handle error

            val error = tokenResponse["error"].asString

            logger.error("Token Endpoint returned: $error")

            throw AuthenticationServiceException("Unable to obtain Access Token.  Token Endpoint returned: $error")
        } else {
            // Extract the id_token to insert into the
            // OIDCAuthenticationToken

            // get out all the token strings

            var accessTokenValue: String? = null
            var idTokenValue: String? = null
            var refreshTokenValue: String? = null

            if (tokenResponse.has("access_token")) {
                accessTokenValue = tokenResponse["access_token"].asString
            } else {
                throw AuthenticationServiceException("Token Endpoint did not return an access_token: $jsonString")
            }

            if (tokenResponse.has("id_token")) {
                idTokenValue = tokenResponse["id_token"].asString
            } else {
                logger.error("Token Endpoint did not return an id_token")
                throw AuthenticationServiceException("Token Endpoint did not return an id_token")
            }

            if (tokenResponse.has("refresh_token")) {
                refreshTokenValue = tokenResponse["refresh_token"].asString
            }

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
                        throw AuthenticationServiceException("Token algorithm $tokenAlg does not match expected algorithm $clientAlg")
                    }
                }

                if (idToken is PlainJWT) {
                    if (clientAlg == null) {
                        throw AuthenticationServiceException("Unsigned ID tokens can only be used if explicitly configured in client.")
                    }

                    if (tokenAlg != null && tokenAlg != Algorithm.NONE) {
                        throw AuthenticationServiceException("Unsigned token received, expected signature with $tokenAlg")
                    }
                } else if (idToken is SignedJWT) {
                    jwtValidator =
                        if (tokenAlg == JWSAlgorithm.HS256 || tokenAlg == JWSAlgorithm.HS384 || tokenAlg == JWSAlgorithm.HS512) {
                            // generate one based on client secret

                            symmetricCacheService!!.getSymmetricValidtor(clientConfig.client)
                        } else {
                            // otherwise load from the server's public key
                            validationServices!!.getValidator(serverConfig.jwksUri!!)
                        }

                    if (jwtValidator != null) {
                        if (!jwtValidator.validateSignature(idToken)) {
                            throw AuthenticationServiceException("Signature validation failed")
                        }
                    } else {
                        logger.error("No validation service found. Skipping signature validation")
                        throw AuthenticationServiceException("Unable to find an appropriate signature validator for ID Token.")
                    }
                } // TODO: encrypted id tokens


                // check the issuer
                if (idClaims.issuer == null) {
                    throw AuthenticationServiceException("Id Token Issuer is null")
                } else if (idClaims.issuer != serverConfig.issuer) {
                    throw AuthenticationServiceException("Issuers do not match, expected " + serverConfig.issuer + " got " + idClaims.issuer)
                }

                // check expiration
                if (idClaims.expirationTime == null) {
                    throw AuthenticationServiceException("Id Token does not have required expiration claim")
                } else {
                    // it's not null, see if it's expired
                    val now = Date(System.currentTimeMillis() - (timeSkewAllowance * 1000))
                    if (now.after(idClaims.expirationTime)) {
                        throw AuthenticationServiceException("Id Token is expired: " + idClaims.expirationTime)
                    }
                }

                // check not before
                if (idClaims.notBeforeTime != null) {
                    val now = Date(System.currentTimeMillis() + (timeSkewAllowance * 1000))
                    if (now.before(idClaims.notBeforeTime)) {
                        throw AuthenticationServiceException("Id Token not valid untill: " + idClaims.notBeforeTime)
                    }
                }

                // check issued at
                if (idClaims.issueTime == null) {
                    throw AuthenticationServiceException("Id Token does not have required issued-at claim")
                } else {
                    // since it's not null, see if it was issued in the future
                    val now = Date(System.currentTimeMillis() + (timeSkewAllowance * 1000))
                    if (now.before(idClaims.issueTime)) {
                        throw AuthenticationServiceException("Id Token was issued in the future: " + idClaims.issueTime)
                    }
                }

                // check audience
                if (idClaims.audience == null) {
                    throw AuthenticationServiceException("Id token audience is null")
                } else if (!idClaims.audience.contains(clientConfig.clientId)) {
                    throw AuthenticationServiceException("Audience does not match, expected " + clientConfig.clientId + " got " + idClaims.audience)
                }

                // compare the nonce to our stored claim
                val nonce = idClaims.getStringClaim("nonce")
                if (nonce.isNullOrEmpty()) {
                    logger.error("ID token did not contain a nonce claim.")

                    throw AuthenticationServiceException("ID token did not contain a nonce claim.")
                }

                val storedNonce = getStoredNonce(session)
                if (nonce != storedNonce) {
                    logger.error(
                        "Possible replay attack detected! The comparison of the nonce in the returned "
                                + "ID Token to the session " + NONCE_SESSION_VARIABLE + " failed. Expected " + storedNonce + " got " + nonce + "."
                    )

                    throw AuthenticationServiceException(
                        "Possible replay attack detected! The comparison of the nonce in the returned "
                                + "ID Token to the session " + NONCE_SESSION_VARIABLE + " failed. Expected " + storedNonce + " got " + nonce + "."
                    )
                }

                // construct an PendingOIDCAuthenticationToken and return a Authentication object w/the userId and the idToken
                val token = PendingOIDCAuthenticationToken(
                    idClaims.subject, idClaims.issuer,
                    serverConfig,
                    idToken, accessTokenValue, refreshTokenValue!!
                )

                val authentication = authenticationManager.authenticate(token)

                return authentication
            } catch (e: ParseException) {
                throw AuthenticationServiceException("Couldn't parse idToken: ", e)
            }
        }
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
    protected fun handleError(request: HttpServletRequest, response: HttpServletResponse?) {
        val error = request.getParameter("error")
        val errorDescription = request.getParameter("error_description")
        val errorURI = request.getParameter("error_uri")

        throw AuthorizationEndpointException(error, errorDescription, errorURI)
    }

    override fun setAuthenticationSuccessHandler(successHandler: AuthenticationSuccessHandler) {
        targetLinkURIAuthenticationSuccessHandler.passthrough = successHandler
        super.setAuthenticationSuccessHandler(targetLinkURIAuthenticationSuccessHandler)
    }


    /**
     * Handle a successful authentication event. If the issuer service sets
     * a target URL, we'll go to that. Otherwise we'll let the superclass handle
     * it for us with the configured behavior.
     */
    inner class TargetLinkURIAuthenticationSuccessHandler : AuthenticationSuccessHandler {
        var passthrough: AuthenticationSuccessHandler? = null

        @Throws(IOException::class, ServletException::class)
        override fun onAuthenticationSuccess(
            request: HttpServletRequest,
            response: HttpServletResponse, authentication: Authentication
        ) {
            val session = request.session

            // check to see if we've got a target
            var target = getStoredSessionString(session, TARGET_SESSION_VARIABLE)

            if (!target.isNullOrEmpty()) {
                session.removeAttribute(TARGET_SESSION_VARIABLE)

                if (deepLinkFilter != null) {
                    target = deepLinkFilter!!.filter(target)
                }

                response.sendRedirect(target)
            } else {
                // if the target was blank, use the default behavior here
                passthrough!!.onAuthenticationSuccess(request, response, authentication)
            }
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

        /**
         * Get the named stored session variable as a string. Return null if not found or not a string.
         */
        private fun getStoredSessionString(session: HttpSession, key: String): String? {
            val o = session.getAttribute(key)
            return if (o != null && o is String) {
                o.toString()
            } else {
                null
            }
        }

        /**
         * Create a cryptographically random nonce and store it in the session
         */
        protected fun createNonce(session: HttpSession): String {
            val nonce = BigInteger(50, SecureRandom()).toString(16)
            session.setAttribute(NONCE_SESSION_VARIABLE, nonce)

            return nonce
        }

        /**
         * Get the nonce we stored in the session
         */
        protected fun getStoredNonce(session: HttpSession): String? {
            return getStoredSessionString(session, NONCE_SESSION_VARIABLE)
        }

        /**
         * Create a cryptographically random state and store it in the session
         */
        protected fun createState(session: HttpSession): String {
            val state = BigInteger(50, SecureRandom()).toString(16)
            session.setAttribute(STATE_SESSION_VARIABLE, state)

            return state
        }

        /**
         * Get the state we stored in the session
         */
        protected fun getStoredState(session: HttpSession): String? {
            return getStoredSessionString(session, STATE_SESSION_VARIABLE)
        }

        /**
         * Create a random code challenge and store it in the session
         */
        protected fun createCodeVerifier(session: HttpSession): String {
            val challenge = BigInteger(50, SecureRandom()).toString(16)
            session.setAttribute(CODE_VERIFIER_SESSION_VARIABLE, challenge)
            return challenge
        }

        /**
         * Retrieve the stored challenge from our session
         */
        protected fun getStoredCodeVerifier(session: HttpSession): String? {
            return getStoredSessionString(session, CODE_VERIFIER_SESSION_VARIABLE)
        }
    }
}
