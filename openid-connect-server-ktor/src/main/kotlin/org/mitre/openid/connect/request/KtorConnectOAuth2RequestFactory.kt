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
import io.ktor.server.auth.*
import kotlinx.serialization.json.JsonObject
import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService
import org.mitre.jwt.signer.service.impl.ClientKeyCacheService
import org.mitre.oauth2.exception.InvalidClientException
import org.mitre.oauth2.model.PKCEAlgorithm
import org.mitre.oauth2.model.convert.OAuth2Request
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.openid.connect.request.ConnectRequestParameters.AUD
import org.mitre.openid.connect.request.ConnectRequestParameters.CLIENT_ID
import org.mitre.openid.connect.request.ConnectRequestParameters.CODE_CHALLENGE
import org.mitre.openid.connect.request.ConnectRequestParameters.LOGIN_HINT
import org.mitre.openid.connect.request.ConnectRequestParameters.MAX_AGE
import org.mitre.openid.connect.request.ConnectRequestParameters.REQUEST
import org.mitre.openid.connect.service.MITREidDataService
import org.mitre.util.getLogger
import java.text.ParseException


// TODO Spring specific
class KtorConnectOAuth2RequestFactory constructor(
    clientDetailsService: ClientDetailsEntityService,
    val validators: ClientKeyCacheService,
    val encryptionService: JWTEncryptionAndDecryptionService,
) : KtorOAuth2RequestFactory(
    clientDetailsService,
) {
    override fun createAuthorizationRequest(inputParams: Parameters): OAuth2Request {
        val baseRequest =  super.createAuthorizationRequest(inputParams)

        val jwt = inputParams[REQUEST]?.let { parseToJwt(it, baseRequest) }

        val finalClientId = baseRequest.clientId.takeIf { it.isNotBlank() }
            ?: jwt?.run { jwtClaimsSet.getStringClaim(CLIENT_ID).takeIf { it.isNotBlank() } }

        val client = finalClientId?.let { clientDetailsService.loadClientByClientId(it) }

        val extensions = buildMap<String, String> {

            inputParams[ConnectRequestParameters.PROMPT]?.let { put(ConnectRequestParameters.PROMPT, it) }
            inputParams[ConnectRequestParameters.NONCE]?.let { put(ConnectRequestParameters.NONCE, it) }
            parseClaimRequest(inputParams[ConnectRequestParameters.CLAIMS])?.let {
                put(ConnectRequestParameters.CLAIMS, it.toString())
            }
            inputParams[MAX_AGE]?.let { put(MAX_AGE, it) }
            inputParams[LOGIN_HINT]?.let { put(LOGIN_HINT, it) }
            inputParams[AUD]?.let { put(AUD, it) }

            inputParams[CODE_CHALLENGE]?.let { codeChallenge ->
                put(CODE_CHALLENGE, codeChallenge)
                val challengeMethod = inputParams[ConnectRequestParameters.CODE_CHALLENGE_METHOD]
                put(ConnectRequestParameters.CODE_CHALLENGE_METHOD, challengeMethod ?: PKCEAlgorithm.plain.name)

            }

            if (jwt != null) {
                processRequestObject(jwt.jwtClaimsSet, baseRequest)
            }

            if (client!=null && baseRequest.extensions[MAX_AGE] == null && client.defaultMaxAge != null) {
                put(MAX_AGE, client.defaultMaxAge.toString())
            }
        }
        val newResponseTypes = jwt?.let { processResponseTypes(it.jwtClaimsSet, baseRequest) } ?: baseRequest.responseTypes
        val newRedirectUri = jwt?.let{ processRedirectUri(it.jwtClaimsSet, baseRequest) } ?: baseRequest.redirectUri
        val newState = jwt?.let { processState(it.jwtClaimsSet, baseRequest) } ?: baseRequest.state
        val newScope = jwt?.let { processScope(it.jwtClaimsSet, baseRequest) }
            ?: baseRequest.scope.takeIf { it.isNotEmpty() }
            ?: client?.scope
            ?: emptySet()

        //Add extension parameters to the 'extensions' map





        return baseRequest.copy(
            clientId = finalClientId ?: "",
            scope = newScope,
            redirectUri = newRedirectUri,
            responseTypes = newResponseTypes,
            state = newState,
            extensionStrings = extensions,
        )
    }

    private fun parseToJwt(jwtString: String, request: OAuth2Request): JWT {
        val jwt = JWTParser.parse(jwtString)

        when (jwt) {
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
                    ?: throw InvalidClientException("Unable to create signature validator for client $client and " +
                                                            "algorithm $alg")

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
                        throw InvalidClientException("Client is not registered for unsigned request objects " +
                                "(no request_object_signing_alg registered)")

                    Algorithm.NONE -> return jwt // if we got here, we're OK, keep processing

                    else -> throw InvalidClientException("Client is not registered for unsigned request objects " +
                                "(request_object_signing_alg is ${client.requestObjectSigningAlg})")
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

    private fun processResponseTypes(claims: JWTClaimsSet, request: OAuth2Request): Set<String>? {
        val responseTypes = claims.getStringClaim(ConnectRequestParameters.RESPONSE_TYPE)
            ?.splitToSequence(' ')?.filterNotTo(HashSet()) { it.isBlank() }

        if (!responseTypes.isNullOrEmpty()) {
            // TODO check that this is actually equal
            if (responseTypes != request.responseTypes) {
                logger.info("Mismatch between request object and regular parameter for response_type, using request object")
            }
            return responseTypes
        }
        return request.responseTypes
    }

    private fun processRedirectUri(claims: JWTClaimsSet, request: OAuth2Request): String? {
        val redirectUri = claims.getStringClaim(ConnectRequestParameters.REDIRECT_URI)
        if (redirectUri != null) {
            if (redirectUri != request.redirectUri) {
                logger.info("Mismatch between request object and regular parameter for redirect_uri, using request object")
            }
            return redirectUri
        }
        return request.redirectUri
    }

    private fun MutableMap<String, String>.processRequestObject(
        claims: JWTClaimsSet,
        request: OAuth2Request
    ) {
        val extensions = this
        // parse the request object

        try {

            val nonce = claims.getStringClaim(ConnectRequestParameters.NONCE)
            if (nonce != null) {
                if (nonce != extensions[ConnectRequestParameters.NONCE]) {
                    logger.info("Mismatch between request object and regular parameter for nonce, using request object")
                }
                extensions[ConnectRequestParameters.NONCE] = nonce
            }

            val display = claims.getStringClaim(ConnectRequestParameters.DISPLAY)
            if (display != null) {
                if (display != extensions[ConnectRequestParameters.DISPLAY]) {
                    logger.info("Mismatch between request object and regular parameter for display, using request object")
                }
                extensions[ConnectRequestParameters.DISPLAY] = display
            }

            val prompt = claims.getStringClaim(ConnectRequestParameters.PROMPT)
            if (prompt != null) {
                if (prompt != extensions[ConnectRequestParameters.PROMPT]) {
                    logger.info("Mismatch between request object and regular parameter for prompt, using request object")
                }
                extensions[ConnectRequestParameters.PROMPT] = prompt
            }

            val claimRequest = parseClaimRequest(claims.getStringClaim(ConnectRequestParameters.CLAIMS))
            if (claimRequest != null) {
                val claimExtension = extensions[ConnectRequestParameters.CLAIMS]
                if (claimExtension == null || claimRequest != parseClaimRequest(claimExtension.toString())) {
                    logger.info("Mismatch between request object and regular parameter for claims, using request object")
                }
                // we save the string because the object might not be a Java Serializable, and we can parse it easily enough anyway
                extensions[ConnectRequestParameters.CLAIMS] = claimRequest.toString()
            }

            val loginHint = claims.getStringClaim(LOGIN_HINT)
            if (loginHint != null) {
                if (loginHint != extensions[LOGIN_HINT]) {
                    logger.info("Mistmatch between request object and regular parameter for login_hint, using requst object")
                }
                extensions[LOGIN_HINT] = loginHint
            }
        } catch (e: ParseException) {
            logger.error("ParseException while parsing RequestObject:", e)
        }
    }

    private fun processState(claims: JWTClaimsSet, request: OAuth2Request): String? {
        val state = claims.getStringClaim(ConnectRequestParameters.STATE)
        if (state != null) {
            if (state != request.state) {
                logger.info("Mismatch between request object and regular parameter for state, using request object")
            }
            return state
        }
        return request.state
    }

    private fun processScope(claims: JWTClaimsSet, request: OAuth2Request): Set<String> {
        val scope = claims.getStringClaim(ConnectRequestParameters.SCOPE).splitToSequence(' ')
            .filterNotTo(HashSet()) { it.isBlank() }
        if (scope.isNotEmpty()) {
            if (scope != request.scope) {
                logger.info("Mismatch between request object and regular parameter for scope, using request object")
            }
            return scope
        }
        return request.scope
    }


    private fun parseClaimRequest(claimRequestString: String?): JsonObject? {
        if (claimRequestString.isNullOrEmpty()) {
            return null
        }

        return MITREidDataService.json.parseToJsonElement(claimRequestString) as? JsonObject
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<KtorConnectOAuth2RequestFactory>()
    }
}
