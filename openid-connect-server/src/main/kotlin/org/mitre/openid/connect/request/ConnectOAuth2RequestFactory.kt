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
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.json.JsonObject
import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService
import org.mitre.jwt.signer.service.impl.ClientKeyCacheService
import org.mitre.oauth2.model.PKCEAlgorithm
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.SpringClientDetailsEntityService
import org.mitre.openid.connect.service.MITREidDataService
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.oauth2.common.exceptions.InvalidClientException
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception
import org.springframework.security.oauth2.common.util.OAuth2Utils
import org.springframework.security.oauth2.provider.AuthorizationRequest
import org.springframework.security.oauth2.provider.ClientDetailsService
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory
import org.springframework.stereotype.Component
import java.text.ParseException


// TODO Spring specific
@Component("connectOAuth2RequestFactory")
class ConnectOAuth2RequestFactory @Autowired constructor(
    private val clientDetailsService: SpringClientDetailsEntityService
) : DefaultOAuth2RequestFactory(clientDetailsService) {

    @Autowired
    private lateinit var validators: ClientKeyCacheService

    @Autowired
    private lateinit var encryptionService: JWTEncryptionAndDecryptionService

    override fun createAuthorizationRequest(inputParams: Map<String, String>): AuthorizationRequest {
        val request = AuthorizationRequest(
            inputParams, emptyMap(),
            inputParams[OAuth2Utils.CLIENT_ID],
            OAuth2Utils.parseParameterList(inputParams[OAuth2Utils.SCOPE]), null,
            null, false, inputParams[OAuth2Utils.STATE],
            inputParams[OAuth2Utils.REDIRECT_URI],
            OAuth2Utils.parseParameterList(inputParams[OAuth2Utils.RESPONSE_TYPE])
        )

        //Add extension parameters to the 'extensions' map
        if (inputParams.containsKey(ConnectRequestParameters.PROMPT)) {
            request.extensions[ConnectRequestParameters.PROMPT] = inputParams[ConnectRequestParameters.PROMPT]
        }
        if (inputParams.containsKey(ConnectRequestParameters.NONCE)) {
            request.extensions[ConnectRequestParameters.NONCE] = inputParams[ConnectRequestParameters.NONCE]
        }

        if (inputParams.containsKey(ConnectRequestParameters.CLAIMS)) {
            val claimsRequest = parseClaimRequest(inputParams[ConnectRequestParameters.CLAIMS])
            if (claimsRequest != null) {
                request.extensions[ConnectRequestParameters.CLAIMS] = claimsRequest.toString()
            }
        }

        if (inputParams.containsKey(ConnectRequestParameters.MAX_AGE)) {
            request.extensions[ConnectRequestParameters.MAX_AGE] = inputParams[ConnectRequestParameters.MAX_AGE]
        }

        if (inputParams.containsKey(ConnectRequestParameters.LOGIN_HINT)) {
            request.extensions[ConnectRequestParameters.LOGIN_HINT] = inputParams[ConnectRequestParameters.LOGIN_HINT]
        }

        if (inputParams.containsKey(ConnectRequestParameters.AUD)) {
            request.extensions[ConnectRequestParameters.AUD] = inputParams[ConnectRequestParameters.AUD]
        }

        if (inputParams.containsKey(ConnectRequestParameters.CODE_CHALLENGE)) {
            request.extensions[ConnectRequestParameters.CODE_CHALLENGE] =
                inputParams[ConnectRequestParameters.CODE_CHALLENGE]
            if (inputParams.containsKey(ConnectRequestParameters.CODE_CHALLENGE_METHOD)) {
                request.extensions[ConnectRequestParameters.CODE_CHALLENGE_METHOD] =
                    inputParams[ConnectRequestParameters.CODE_CHALLENGE_METHOD]
            } else {
                // if the client doesn't specify a code challenge transformation method, it's "plain"
                request.extensions[ConnectRequestParameters.CODE_CHALLENGE_METHOD] = PKCEAlgorithm.plain.name
            }
        }

        if (inputParams.containsKey(ConnectRequestParameters.REQUEST)) {
            request.extensions[ConnectRequestParameters.REQUEST] = inputParams[ConnectRequestParameters.REQUEST]
            processRequestObject(inputParams[ConnectRequestParameters.REQUEST], request)
        }

        if (request.clientId != null) {
            try {
                val client = clientDetailsService.loadClientByClientId(request.clientId)

                if ((request.scope == null || request.scope.isEmpty())) {
                    val clientScopes: Set<String> = client!!.scope
                    request.setScope(clientScopes)
                }

                if (request.extensions[ConnectRequestParameters.MAX_AGE] == null && client!!.defaultMaxAge != null) {
                    request.extensions[ConnectRequestParameters.MAX_AGE] = client.defaultMaxAge.toString()
                }
            } catch (e: OAuth2Exception) {
                logger.error("Caught OAuth2 exception trying to test client scopes and max age:", e)
            }
        }

        return request
    }


    private fun processRequestObject(jwtString: String?, request: AuthorizationRequest) {
        // parse the request object

        try {
            val jwt = JWTParser.parse(jwtString)

            if (jwt is SignedJWT) {
                // it's a signed JWT, check the signature

                val signedJwt = jwt

                // need to check clientId first so that we can load the client to check other fields
                if (request.clientId == null) {
                    request.clientId = signedJwt.jwtClaimsSet.getStringClaim(ConnectRequestParameters.CLIENT_ID)
                }

                val client = clientDetailsService.loadClientByClientId(request.clientId)
                    ?: throw InvalidClientException("Client not found: " + request.clientId)


                val alg = signedJwt.header.algorithm

                if (client.requestObjectSigningAlg == null ||
                    client.requestObjectSigningAlg != alg
                ) {
                    throw InvalidClientException("Client's registered request object signing algorithm (" + client.requestObjectSigningAlg + ") does not match request object's actual algorithm (" + alg.name + ")")
                }

                val validator = validators.getValidator(client, alg)
                    ?: throw InvalidClientException("Unable to create signature validator for client $client and algorithm $alg")

                if (!validator.validateSignature(signedJwt)) {
                    throw InvalidClientException("Signature did not validate for presented JWT request object.")
                }
            } else if (jwt is PlainJWT) {
                // need to check clientId first so that we can load the client to check other fields
                if (request.clientId == null) {
                    request.clientId = jwt.jwtClaimsSet.getStringClaim(ConnectRequestParameters.CLIENT_ID)
                }

                val client = clientDetailsService.loadClientByClientId(request.clientId)
                    ?: throw InvalidClientException("Client not found: " + request.clientId)

                if (client.requestObjectSigningAlg == null) {
                    throw InvalidClientException("Client is not registered for unsigned request objects (no request_object_signing_alg registered)")
                } else if (client.requestObjectSigningAlg != Algorithm.NONE) {
                    throw InvalidClientException("Client is not registered for unsigned request objects (request_object_signing_alg is " + client.requestObjectSigningAlg + ")")
                }

                // if we got here, we're OK, keep processing
            } else if (jwt is EncryptedJWT) {
                val encryptedJWT = jwt

                // decrypt the jwt if we can
                encryptionService!!.decryptJwt(encryptedJWT)

                // TODO: what if the content is a signed JWT? (#525)
                if (encryptedJWT.state != JWEObject.State.DECRYPTED) {
                    throw InvalidClientException("Unable to decrypt the request object")
                }

                // need to check clientId first so that we can load the client to check other fields
                if (request.clientId == null) {
                    request.clientId = encryptedJWT.jwtClaimsSet.getStringClaim(ConnectRequestParameters.CLIENT_ID)
                }

                val client = clientDetailsService.loadClientByClientId(request.clientId)
                    ?: throw InvalidClientException("Client not found: " + request.clientId)
            }


            /*
             * NOTE: Claims inside the request object always take precedence over those in the parameter map.
             */

            // now that we've got the JWT, and it's been parsed, validated, and/or decrypted, we can process the claims
            val claims = jwt.jwtClaimsSet

            val responseTypes =
                OAuth2Utils.parseParameterList(claims.getStringClaim(ConnectRequestParameters.RESPONSE_TYPE))
            if (!responseTypes.isEmpty()) {
                if (responseTypes != request.responseTypes) {
                    logger.info("Mismatch between request object and regular parameter for response_type, using request object")
                }
                request.responseTypes = responseTypes
            }

            val redirectUri = claims.getStringClaim(ConnectRequestParameters.REDIRECT_URI)
            if (redirectUri != null) {
                if (redirectUri != request.redirectUri) {
                    logger.info("Mismatch between request object and regular parameter for redirect_uri, using request object")
                }
                request.redirectUri = redirectUri
            }

            val state = claims.getStringClaim(ConnectRequestParameters.STATE)
            if (state != null) {
                if (state != request.state) {
                    logger.info("Mismatch between request object and regular parameter for state, using request object")
                }
                request.state = state
            }

            val nonce = claims.getStringClaim(ConnectRequestParameters.NONCE)
            if (nonce != null) {
                if (nonce != request.extensions[ConnectRequestParameters.NONCE]) {
                    logger.info("Mismatch between request object and regular parameter for nonce, using request object")
                }
                request.extensions[ConnectRequestParameters.NONCE] = nonce
            }

            val display = claims.getStringClaim(ConnectRequestParameters.DISPLAY)
            if (display != null) {
                if (display != request.extensions[ConnectRequestParameters.DISPLAY]) {
                    logger.info("Mismatch between request object and regular parameter for display, using request object")
                }
                request.extensions[ConnectRequestParameters.DISPLAY] = display
            }

            val prompt = claims.getStringClaim(ConnectRequestParameters.PROMPT)
            if (prompt != null) {
                if (prompt != request.extensions[ConnectRequestParameters.PROMPT]) {
                    logger.info("Mismatch between request object and regular parameter for prompt, using request object")
                }
                request.extensions[ConnectRequestParameters.PROMPT] = prompt
            }

            val scope = OAuth2Utils.parseParameterList(claims.getStringClaim(ConnectRequestParameters.SCOPE))
            if (!scope.isEmpty()) {
                if (scope != request.scope) {
                    logger.info("Mismatch between request object and regular parameter for scope, using request object")
                }
                request.setScope(scope)
            }

            val claimRequest = parseClaimRequest(claims.getStringClaim(ConnectRequestParameters.CLAIMS))
            if (claimRequest != null) {
                val claimExtension = request.extensions[ConnectRequestParameters.CLAIMS]
                if (claimExtension == null || claimRequest != parseClaimRequest(claimExtension.toString())) {
                    logger.info("Mismatch between request object and regular parameter for claims, using request object")
                }
                // we save the string because the object might not be a Java Serializable, and we can parse it easily enough anyway
                request.extensions[ConnectRequestParameters.CLAIMS] = claimRequest.toString()
            }

            val loginHint = claims.getStringClaim(ConnectRequestParameters.LOGIN_HINT)
            if (loginHint != null) {
                if (loginHint != request.extensions[ConnectRequestParameters.LOGIN_HINT]) {
                    logger.info("Mistmatch between request object and regular parameter for login_hint, using requst object")
                }
                request.extensions[ConnectRequestParameters.LOGIN_HINT] = loginHint
            }
        } catch (e: ParseException) {
            logger.error("ParseException while parsing RequestObject:", e)
        }
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
        private val logger: Logger = LoggerFactory.getLogger(ConnectOAuth2RequestFactory::class.java)
    }
}
