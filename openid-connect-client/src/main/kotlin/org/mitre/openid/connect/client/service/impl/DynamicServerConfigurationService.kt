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
package org.mitre.openid.connect.client.service.impl

import io.github.pdvrieze.client.onError
import io.github.pdvrieze.oidc.util.CoroutineCache
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import org.mitre.openid.connect.client.AuthenticationServiceException
import org.mitre.openid.connect.client.service.ServerConfigurationService
import org.mitre.openid.connect.config.ServerConfiguration
import org.mitre.util.asBoolean
import org.mitre.util.asEncryptionMethodList
import org.mitre.util.asJweAlgorithmList
import org.mitre.util.asJwsAlgorithmList
import org.mitre.util.asString
import org.mitre.util.asStringList
import org.mitre.util.asStringOrNull
import org.mitre.util.getLogger
import java.util.concurrent.ExecutionException

/**
 *
 * Dynamically fetches OpenID Connect server configurations based on the issuer. Caches the server configurations.
 *
 * @author jricher
 */
class DynamicServerConfigurationService(
    private val httpClient: HttpClient = HttpClient(CIO)
) : ServerConfigurationService {

    private val servers = CoroutineCache<String, ServerConfiguration>(::loadImpl)

    var whitelist: Set<String?> = HashSet()
    var blacklist: Set<String?> = HashSet()

    override suspend fun getServerConfiguration(issuer: String): ServerConfiguration? {
        try {
            if (whitelist.isNotEmpty() && issuer !in whitelist) {
                throw AuthenticationServiceException("Whitelist was nonempty, issuer was not in whitelist: $issuer")
            }

            if (issuer in blacklist) {
                throw AuthenticationServiceException("Issuer was in blacklist: $issuer")
            }

            return servers.load(issuer)
        } catch (e: ExecutionException) {
            logger.warn("Couldn't load configuration for $issuer: $e")
        }
        return null
    }

    @Throws(Exception::class)
    private suspend fun loadImpl(issuer: String): ServerConfiguration {

        // data holder
        val conf = ServerConfiguration()

        // construct the well-known URI
        val url = "$issuer/.well-known/openid-configuration"

        val resp = httpClient.get(url).onError { throw IllegalStateException("Could not get server information; $it") }


        val o = (Json.parseToJsonElement(resp.bodyAsText()) as? JsonObject)
            ?: throw IllegalStateException("Couldn't parse server discovery results for $url")

        val parsedIssuer = o["issuer"]?.asString()
        // sanity checks
        checkNotNull(parsedIssuer) { "Returned object did not have an 'issuer' field" }


        if (issuer != parsedIssuer) {
            logger.info("Issuer used for discover was $issuer but final issuer is $parsedIssuer")
        }

        conf.issuer = parsedIssuer


        conf.authorizationEndpointUri = o["authorization_endpoint"]?.asStringOrNull()
        conf.tokenEndpointUri = o["token_endpoint"]?.asStringOrNull()
        conf.jwksUri = requireNotNull(o["jwks_uri"]) { "Missing required configuration item: jwks_uri" }.asString()
        conf.userInfoUri = o["userinfo_endpoint"]?.asStringOrNull()
        conf.registrationEndpointUri = o["registration_endpoint"]?.asStringOrNull()
        conf.introspectionEndpointUri = o["introspection_endpoint"]?.asStringOrNull()
        conf.acrValuesSupported = o["acr_values_supported"].asStringList()
        conf.checkSessionIframe = o["check_session_iframe"]?.asStringOrNull()
        conf.claimsLocalesSupported = o["claims_locales_supported"].asStringList()
        conf.claimsParameterSupported = requireNotNull(o["claims_parameter_supported"]).asBoolean()
        conf.claimsSupported = o["claims_supported"].asStringList()
        conf.displayValuesSupported = o["display_values_supported"].asStringList()
        conf.endSessionEndpoint = o["end_session_endpoint"]?.asStringOrNull()
        conf.grantTypesSupported = o["grant_types_supported"].asStringList()
        conf.idTokenSigningAlgValuesSupported =
            o["id_token_signing_alg_values_supported"].asJwsAlgorithmList()!!
        conf.idTokenEncryptionAlgValuesSupported =
            o["id_token_encryption_alg_values_supported"].asJweAlgorithmList()
        conf.idTokenEncryptionEncValuesSupported =
            o["id_token_encryption_enc_values_supported"].asEncryptionMethodList()
        conf.opPolicyUri = o["op_policy_uri"]?.asStringOrNull()
        conf.opTosUri = o["op_tos_uri"]?.asStringOrNull()
        conf.requestObjectEncryptionAlgValuesSupported =
            o["request_object_encryption_alg_values_supported"].asJweAlgorithmList()
        conf.requestObjectEncryptionEncValuesSupported =
            o["request_object_encryption_enc_values_supported"].asEncryptionMethodList()
        conf.requestObjectSigningAlgValuesSupported =
            o["request_object_signing_alg_values_supported"].asJwsAlgorithmList()
        conf.requestParameterSupported = o["request_parameter_supported"]?.asBoolean()!!
        conf.requestUriParameterSupported = o["request_uri_parameter_supported"]?.asBoolean()!!
        conf.responseTypesSupported = o["response_types_supported"].asStringList()!!
        conf.scopesSupported = o["scopes_supported"].asStringList()
        conf.subjectTypesSupported = o["subject_types_supported"].asStringList()!!
        conf.serviceDocumentation = o["service_documentation"]?.asStringOrNull()
        conf.tokenEndpointAuthMethodsSupported = o["token_endpoint_auth_methods"].asStringList()
        conf.tokenEndpointAuthSigningAlgValuesSupported =
            o["token_endpoint_auth_signing_alg_values_supported"].asJwsAlgorithmList()
        conf.uiLocalesSupported = o["ui_locales_supported"].asStringList()
        conf.userinfoEncryptionAlgValuesSupported =
            o["userinfo_encryption_alg_values_supported"].asJweAlgorithmList()
        conf.userinfoEncryptionEncValuesSupported =
            o["userinfo_encryption_enc_values_supported"].asEncryptionMethodList()
        conf.userinfoSigningAlgValuesSupported =
            o["userinfo_signing_alg_values_supported"].asJwsAlgorithmList()

        return conf
    }


    companion object {
        private val logger = getLogger<DynamicServerConfigurationService>()
    }
}
