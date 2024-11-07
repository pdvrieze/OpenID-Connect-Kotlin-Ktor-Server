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
 * limStringitations under the License.
 */
package org.mitre.openid.connect.request

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JWEObject
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.jwt.SignedJWT
import io.ktor.http.*
import kotlinx.serialization.json.JsonObject
import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService
import org.mitre.jwt.signer.service.ClientKeyCacheService
import org.mitre.oauth2.exception.InvalidClientException
import org.mitre.oauth2.model.PKCEAlgorithm
import org.mitre.oauth2.model.request.AuthorizationRequest
import org.mitre.oauth2.model.request.CodeChallenge
import org.mitre.oauth2.model.request.OpenIdAuthorizationRequest
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.openid.connect.request.ConnectRequestParameters.AUD
import org.mitre.openid.connect.request.ConnectRequestParameters.CLIENT_ID
import org.mitre.openid.connect.request.ConnectRequestParameters.CODE_CHALLENGE
import org.mitre.openid.connect.request.ConnectRequestParameters.LOGIN_HINT
import org.mitre.openid.connect.request.ConnectRequestParameters.MAX_AGE
import org.mitre.openid.connect.request.ConnectRequestParameters.REQUEST
import org.mitre.openid.connect.service.KtorIdDataService
import org.mitre.util.getLogger


// TODO Spring specific
class KtorConnectOAuth2RequestFactory(
    clientDetailsService: ClientDetailsEntityService,
    val validators: ClientKeyCacheService,
    val encryptionService: JWTEncryptionAndDecryptionService,
) : KtorOAuth2RequestFactory(
    clientDetailsService,
) {
    override suspend fun createAuthorizationRequest(inputParams: Parameters): AuthorizationRequest {
        val reqBuilder = OpenIdAuthorizationRequest.Builder(super.createAuthorizationRequest(inputParams)).apply {
            val jwt = inputParams[REQUEST]?.let { parseToJwt(it, this) }

            // TODO this should not be optional
            if (this.clientId.isBlank()) {
                this.clientId =
                    requireNotNull(jwt?.run { jwtClaimsSet.getStringClaim(CLIENT_ID).takeIf { it.isNotBlank() } }) {
                        "Missing client id"
                    }
            }

            val client = clientDetailsService.loadClientByClientId(this.clientId)

            this.codeChallenge = inputParams[CODE_CHALLENGE]?.let { codeChallenge ->
                val challengeMethod = inputParams[ConnectRequestParameters.CODE_CHALLENGE_METHOD]
                CodeChallenge(codeChallenge, challengeMethod ?: PKCEAlgorithm.plain.name)
            }

            this.audience = inputParams[AUD]
            this.maxAge = inputParams[MAX_AGE]?.toLong() ?: client?.defaultMaxAge

            this.prompts = inputParams[ConnectRequestParameters.PROMPT]?.let { Prompt.parseSet(it) }
            this.nonce = inputParams[ConnectRequestParameters.NONCE]

            this.requestedClaims = parseClaimRequest(inputParams[ConnectRequestParameters.CLAIMS])
            this.maxAge = inputParams[MAX_AGE]?.toLong()
            this.loginHint = inputParams[LOGIN_HINT]
            this.audience = inputParams[AUD]

            if (jwt != null) { // TODO whether this is not just duplicate
                processRequestObject(jwt.jwtClaimsSet, this)
                processResponseTypes(jwt.jwtClaimsSet, this)
                processRedirectUri(jwt.jwtClaimsSet, this)
                processState(jwt.jwtClaimsSet, this)
            }

            scope = jwt?.let { processScope(it.jwtClaimsSet, this) }
                ?: scope.takeIf { it.isNotEmpty() }
                        ?: client?.scope
                        ?: emptySet()
        }

        //Add extension parameters to the 'extensions' map
        return reqBuilder.build()
    }

    private suspend fun parseToJwt(jwtString: String, request: OpenIdAuthorizationRequest.Builder): JWT {
        when (val jwt = JWTParser.parse(jwtString)) {
            is SignedJWT -> {
                // it's a signed JWT, check the signature

                val clientId = request.clientId.takeIf { it.isNotBlank() } ?: jwt.jwtClaimsSet.getStringClaim(CLIENT_ID)
                ?: throw InvalidClientException("No client ID found")

                // need to check clientId first so that we can load the client to check other fields

                val client = clientDetailsService.loadClientByClientId(clientId)
                    ?: throw InvalidClientException("Client not found: ${request.clientId}")


                val alg = jwt.header.algorithm

                if (client.requestObjectSigningAlg != alg
                ) {
                    throw InvalidClientException(
                        "Client's registered request object signing algorithm (${client.requestObjectSigningAlg}) " +
                                "does not match request object's actual algorithm (${alg.name})"
                    )
                }

                val validator = validators.getValidator(client, alg)
                    ?: throw InvalidClientException(
                        "Unable to create signature validator for client $client and " +
                                "algorithm $alg"
                    )

                if (!validator.validateSignature(jwt)) {
                    throw InvalidClientException("Signature did not validate for presented JWT request object.")
                }
                return jwt
            }

            is PlainJWT -> {
                // need to check clientId first so that we can load the client to check other fields
                val clientId = request.clientId.takeIf { it.isNotBlank() }
                    ?: jwt.jwtClaimsSet.getStringClaim(CLIENT_ID)
                    ?: throw InvalidClientException("No client ID found")

                val client = clientDetailsService.loadClientByClientId(clientId)
                    ?: throw InvalidClientException("Client not found: $clientId")

                when (client.requestObjectSigningAlg) {
                    null ->
                        throw InvalidClientException(
                            "Client is not registered for unsigned request objects " +
                                    "(no request_object_signing_alg registered)"
                        )

                    Algorithm.NONE -> return jwt // if we got here, we're OK, keep processing

                    else -> throw InvalidClientException(
                        "Client is not registered for unsigned request objects " +
                                "(request_object_signing_alg is ${client.requestObjectSigningAlg})"
                    )
                }
            }

            is EncryptedJWT -> {

                // decrypt the jwt if we can
                encryptionService.decryptJwt(jwt)

                // TODO: what if the content is a signed JWT? (#525)
                if (jwt.state != JWEObject.State.DECRYPTED) {
                    throw InvalidClientException("Unable to decrypt the request object")
                }

                // need to check clientId first so that we can load the client to check other fields
                val clientId = request.clientId.takeIf { it.isNotBlank() }
                    ?: jwt.jwtClaimsSet.getStringClaim(CLIENT_ID)
                    ?: throw InvalidClientException("No client ID found")

                val client = clientDetailsService.loadClientByClientId(clientId)
                    ?: throw InvalidClientException("Client not found: ${clientId}")
                return jwt
            }
        }
        error("Unexpected JWT type (Neither plain, signed or encrypted)")
    }

    private fun processResponseTypes(claims: JWTClaimsSet, request: OpenIdAuthorizationRequest.Builder) {
        val responseTypes = claims.getStringClaim(ConnectRequestParameters.RESPONSE_TYPE)
            ?.splitToSequence(' ')?.filterNotTo(HashSet()) { it.isBlank() }

        if (!responseTypes.isNullOrEmpty()) {
            // TODO check that this is actually equal
            if (responseTypes != request.responseTypes) {
                logger.info("Mismatch between request object and regular parameter for response_type, using request object")
            }
            request.responseTypes=responseTypes
        }
    }

    private fun processRedirectUri(claims: JWTClaimsSet, request: OpenIdAuthorizationRequest.Builder) {
        val redirectUri = claims.getStringClaim(ConnectRequestParameters.REDIRECT_URI)
        if (redirectUri != null) {
            if (redirectUri != request.redirectUri) {
                logger.info("Mismatch between request object and regular parameter for redirect_uri, using request object")
            }
            request.redirectUri = redirectUri
        }
    }

    private fun processRequestObject(
        claims: JWTClaimsSet,
        request: OpenIdAuthorizationRequest.Builder,
    ) {
        // parse the request object

        val nonce = claims.getStringClaim(ConnectRequestParameters.NONCE)
        if (nonce != null) {
            if (nonce != request.nonce) {
                logger.info("Mismatch between request object and regular parameter for nonce, using request object")
            }
            request.nonce = nonce
        }

        val display = claims.getStringClaim(ConnectRequestParameters.DISPLAY)
        if (display != null) {
            if (display != request.display) {
                logger.info("Mismatch between request object and regular parameter for display, using request object")
            }
            request.display = display
        }

        val prompt = claims.getStringClaim(ConnectRequestParameters.PROMPT)
        if (prompt != null) {
            val prompts = Prompt.parseSet(prompt)
            if (prompts != request.prompts) {
                logger.info("Mismatch between request object and regular parameter for prompt, using request object")
            }
            request.prompts = prompts
        }

        val claimRequest = parseClaimRequest(claims.getStringClaim(ConnectRequestParameters.CLAIMS))
        if (claimRequest != null) {
            val claimExtension = request.requestedClaims
            if (claimRequest != claimExtension) {
                logger.info("Mismatch between request object and regular parameter for claims, using request object")
            }
            // we save the string because the object might not be a Java Serializable, and we can parse it easily enough anyway
            request.requestedClaims = claimRequest
        }

        val loginHint = claims.getStringClaim(LOGIN_HINT)
        if (loginHint != null) {
            if (loginHint != request.loginHint) {
                logger.info("Mistmatch between request object and regular parameter for login_hint, using requst object")
            }
            request.loginHint = loginHint
        }
    }

    private fun processState(claims: JWTClaimsSet, request: OpenIdAuthorizationRequest.Builder) {
        val state = claims.getStringClaim(ConnectRequestParameters.STATE)
        if (state != null) {
            if (state != request.state) {
                logger.info("Mismatch between request object and regular parameter for state, using request object")
            }
            request.state = state
        }
    }

    private fun processScope(claims: JWTClaimsSet, request: OpenIdAuthorizationRequest.Builder): Set<String>? {
        val scope = claims.getStringClaim("scope").splitToSequence(' ')
            .filterNotTo(HashSet()) { it.isBlank() }
        if (scope.isNotEmpty()) {
            if (scope != request.scope) {
                logger.info("Mismatch between request object and regular parameter for scope, using request object")
            }
            return scope
        }
        return null
    }


    private fun parseClaimRequest(claimRequestString: String?): JsonObject? {
        if (claimRequestString.isNullOrEmpty()) {
            return null
        }

        return KtorIdDataService.json.parseToJsonElement(claimRequestString) as? JsonObject
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<KtorConnectOAuth2RequestFactory>()
    }
}
