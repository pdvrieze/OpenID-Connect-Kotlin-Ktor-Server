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

import com.google.common.cache.CacheBuilder
import com.google.common.cache.CacheLoader
import com.google.common.cache.LoadingCache
import com.google.common.util.concurrent.UncheckedExecutionException
import com.google.gson.JsonParser
import org.apache.http.client.HttpClient
import org.apache.http.impl.client.HttpClientBuilder
import org.mitre.openid.connect.client.service.ServerConfigurationService
import org.mitre.openid.connect.config.ServerConfiguration
import org.mitre.util.JsonUtils.getAsBoolean
import org.mitre.util.JsonUtils.getAsEncryptionMethodList
import org.mitre.util.JsonUtils.getAsJweAlgorithmList
import org.mitre.util.JsonUtils.getAsJwsAlgorithmList
import org.mitre.util.JsonUtils.getAsString
import org.mitre.util.JsonUtils.getAsStringList
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory
import org.springframework.security.authentication.AuthenticationServiceException
import org.springframework.web.client.RestTemplate
import java.util.concurrent.ExecutionException

/**
 *
 * Dynamically fetches OpenID Connect server configurations based on the issuer. Caches the server configurations.
 *
 * @author jricher
 */
class DynamicServerConfigurationService @JvmOverloads constructor(
    httpClient: HttpClient? = HttpClientBuilder.create().useSystemProperties().build()
) : ServerConfigurationService {
    // map of issuer -> server configuration, loaded dynamically from service discovery
    // initialize the cache
    private val servers: LoadingCache<String, ServerConfiguration> =
        CacheBuilder.newBuilder().build(OpenIDConnectServiceConfigurationFetcher(httpClient))

    var whitelist: Set<String?> = HashSet()
    var blacklist: Set<String?> = HashSet()

    override fun getServerConfiguration(issuer: String): ServerConfiguration? {
        try {
            if (whitelist.isNotEmpty() && issuer !in whitelist) {
                throw AuthenticationServiceException("Whitelist was nonempty, issuer was not in whitelist: $issuer")
            }

            if (issuer in blacklist) {
                throw AuthenticationServiceException("Issuer was in blacklist: $issuer")
            }

            return servers[issuer]
        } catch (e: UncheckedExecutionException) {
            logger.warn("Couldn't load configuration for $issuer: $e")
        } catch (e: ExecutionException) {
            logger.warn("Couldn't load configuration for $issuer: $e")
        }
        return null
    }

    /**
     * @author jricher
     */
    private inner class OpenIDConnectServiceConfigurationFetcher(httpClient: HttpClient?) :
        CacheLoader<String, ServerConfiguration>() {
        private val httpFactory = HttpComponentsClientHttpRequestFactory(httpClient)
        private val parser = JsonParser()

        @Throws(Exception::class)
        override fun load(issuer: String): ServerConfiguration {
            val restTemplate = RestTemplate(httpFactory)

            // data holder
            val conf = ServerConfiguration()

            // construct the well-known URI
            val url = "$issuer/.well-known/openid-configuration"

            // fetch the value
            val jsonString = restTemplate.getForObject(url, String::class.java)

            val parsed = parser.parse(jsonString)
            if (parsed.isJsonObject) {
                val o = parsed.asJsonObject

                // sanity checks
                check(o.has("issuer")) { "Returned object did not have an 'issuer' field" }

                if (issuer != o["issuer"].asString) {
                    logger.info("Issuer used for discover was " + issuer + " but final issuer is " + o["issuer"].asString)
                }

                conf.issuer = o["issuer"].asString


                conf.authorizationEndpointUri = getAsString(o, "authorization_endpoint")
                conf.tokenEndpointUri = getAsString(o, "token_endpoint")
                conf.jwksUri = getAsString(o, "jwks_uri")
                conf.userInfoUri = getAsString(o, "userinfo_endpoint")
                conf.registrationEndpointUri = getAsString(o, "registration_endpoint")
                conf.introspectionEndpointUri = getAsString(o, "introspection_endpoint")
                conf.acrValuesSupported = getAsStringList(o, "acr_values_supported")
                conf.checkSessionIframe = getAsString(o, "check_session_iframe")
                conf.claimsLocalesSupported = getAsStringList(o, "claims_locales_supported")
                conf.claimsParameterSupported = getAsBoolean(o, "claims_parameter_supported")!!
                conf.claimsSupported = getAsStringList(o, "claims_supported")
                conf.displayValuesSupported = getAsStringList(o, "display_values_supported")
                conf.endSessionEndpoint = getAsString(o, "end_session_endpoint")
                conf.grantTypesSupported = getAsStringList(o, "grant_types_supported")
                conf.idTokenSigningAlgValuesSupported =
                    getAsJwsAlgorithmList(o, "id_token_signing_alg_values_supported")!!
                conf.idTokenEncryptionAlgValuesSupported =
                    getAsJweAlgorithmList(o, "id_token_encryption_alg_values_supported")
                conf.idTokenEncryptionEncValuesSupported =
                    getAsEncryptionMethodList(o, "id_token_encryption_enc_values_supported")
                conf.opPolicyUri = getAsString(o, "op_policy_uri")
                conf.opTosUri = getAsString(o, "op_tos_uri")
                conf.requestObjectEncryptionAlgValuesSupported =
                    getAsJweAlgorithmList(o, "request_object_encryption_alg_values_supported")
                conf.requestObjectEncryptionEncValuesSupported =
                    getAsEncryptionMethodList(o, "request_object_encryption_enc_values_supported")
                conf.requestObjectSigningAlgValuesSupported =
                    getAsJwsAlgorithmList(o, "request_object_signing_alg_values_supported")
                conf.requestParameterSupported = getAsBoolean(o, "request_parameter_supported")!!
                conf.requestUriParameterSupported = getAsBoolean(o, "request_uri_parameter_supported")!!
                conf.responseTypesSupported = getAsStringList(o, "response_types_supported")!!
                conf.scopesSupported = getAsStringList(o, "scopes_supported")
                conf.subjectTypesSupported = getAsStringList(o, "subject_types_supported")!!
                conf.serviceDocumentation = getAsString(o, "service_documentation")
                conf.tokenEndpointAuthMethodsSupported = getAsStringList(o, "token_endpoint_auth_methods")
                conf.tokenEndpointAuthSigningAlgValuesSupported =
                    getAsJwsAlgorithmList(o, "token_endpoint_auth_signing_alg_values_supported")
                conf.uiLocalesSupported = getAsStringList(o, "ui_locales_supported")
                conf.userinfoEncryptionAlgValuesSupported =
                    getAsJweAlgorithmList(o, "userinfo_encryption_alg_values_supported")
                conf.userinfoEncryptionEncValuesSupported =
                    getAsEncryptionMethodList(o, "userinfo_encryption_enc_values_supported")
                conf.userinfoSigningAlgValuesSupported =
                    getAsJwsAlgorithmList(o, "userinfo_signing_alg_values_supported")

                return conf
            } else {
                throw IllegalStateException("Couldn't parse server discovery results for $url")
            }
        }
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(DynamicServerConfigurationService::class.java)
    }
}
