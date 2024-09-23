package org.mitre.discovery.web

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JWSAlgorithm
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addAll
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.mitre.discovery.util.WebfingerURLNormalizer
import org.mitre.discovery.view.webfingerView
import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.oauth2.model.PKCEAlgorithm
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.service.UserInfoService
import org.mitre.util.getLogger
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.OpenIdRouting

/**
 *
 * Handle OpenID Connect Discovery.
 *
 * @author jricher
 */
class DiscoveryEndpoint(
    private val config: ConfigurationPropertiesBean,
    private val scopeService: SystemScopeService,
    private val signService: JWTSigningAndValidationService,
    private val encService: JWTEncryptionAndDecryptionService,
    private val userService: UserInfoService
) : KtorEndpoint {

    // used to map JWA algorithms objects to strings
    private val toAlgorithmName: ((Algorithm) -> String) = { alg -> alg.name }

    override fun Route.addRoutes() {
        getWebfinger()
    }

    private fun Route.getWebfinger() {
        get("/$WEBFINGER_URL") {
            val queryParameters = call.request.queryParameters
            val resource = queryParameters["resource"]
                ?: return@get call.respond(HttpStatusCode.BadRequest, "Missing resource parameter")
            val rel = queryParameters["rel"]?.takeIf { it.isNotEmpty() }
            if (rel != null && rel != "http://openid.net/specs/connect/1.0/issuer") {
                logger.warn("Responding to webfinger request for non-OIDC relation: $rel")
            }

            if (resource != config.issuer) {
                // it's not the issuer directly, need to check other methods

                val resourceUri = WebfingerURLNormalizer.normalizeResource(resource)

                // acct: URI (email address format)
                if (resourceUri?.scheme != "acct") {
                    logger.info("Unknown URI format: $resource")
                    return@get call.respond(HttpStatusCode.NotFound)
                }

                // check on email addresses first

                var user = userService.getByEmailAddress("${resourceUri.userInfo}@${resourceUri.host}")
                    ?: resourceUri.userInfo?.let { userService.getByUsername(it) } // first part is the username
                    ?: run {
                        // if the user's still null, punt and say we didn't find them

                        logger.info("User not found: $resource")
                        return@get call.respond(HttpStatusCode.NotFound)
                    }

                // username matched, check the host component
                val issuerComponents = Url.invoke(config.issuer)

                if (issuerComponents.host != (resourceUri.host ?: "")) {
                    logger.info("Host mismatch, expected ${issuerComponents.host} got ${resourceUri.host}")
                    return@get call.respond(HttpStatusCode.NotFound)
                }
            }

            webfingerView(resource, config.issuer)
        }
    }

    fun Route.getProviderConfiguration() {
        get("/$OPENID_CONFIGURATION_URL") {
            /*
                issuer
                    REQUIRED. URL using the https scheme with no query or fragment component that the OP asserts as its Issuer Identifier.
                authorization_endpoint
                    OPTIONAL. URL of the OP's Authentication and Authorization Endpoint [OpenID.Messages].
                token_endpoint
                    OPTIONAL. URL of the OP's OAuth 2.0 Token Endpoint [OpenID.Messages].
                userinfo_endpoint
                    RECOMMENDED. URL of the OP's UserInfo Endpoint [OpenID.Messages]. This URL MUST use the https scheme
                    and MAY contain port, path, and query parameter components.
                check_session_iframe
                    OPTIONAL. URL of an OP endpoint that provides a page to support cross-origin communications for session state information with
                    the RP Client, using the HTML5 postMessage API. The page is loaded from an invisible iframe embedded in an RP page so that
                    it can run in the OP's security context. See [OpenID.Session].
                end_session_endpoint
                    OPTIONAL. URL of the OP's endpoint that initiates logging out the End-User. See [OpenID.Session].
                jwks_uri
                    REQUIRED. URL of the OP's JSON Web Key Set [JWK] document. This contains the signing key(s) the Client uses to
                    validate signatures from the OP. The JWK Set MAY also contain the Server's encryption key(s),
                    which are used by Clients to encrypt requests to the Server. When both signing and encryption keys are made available,
                    a use (Key Use) parameter value is REQUIRED for all keys in the document to indicate each key's intended usage.
                registration_endpoint
                    RECOMMENDED. URL of the OP's Dynamic Client Registration Endpoint [OpenID.Registration].
                scopes_supported
                    RECOMMENDED. JSON array containing a list of the OAuth 2.0 [RFC6749] scope values that this server supports.
                    The server MUST support the openid scope value.
                response_types_supported
                    REQUIRED. JSON array containing a list of the OAuth 2.0 response_type values that this server supports.
                    The server MUST support the code, id_token, and the token id_token response type values.
                grant_types_supported
                    OPTIONAL. JSON array containing a list of the OAuth 2.0 grant type values that this server supports.
                    The server MUST support the authorization_code and implicit grant type values
                    and MAY support the urn:ietf:params:oauth:grant-type:jwt-bearer grant type defined in OAuth JWT Bearer Token Profiles [OAuth.JWT].
                    If omitted, the default value is ["authorization_code", "implicit"].
                acr_values_supported
                    OPTIONAL. JSON array containing a list of the Authentication Context Class References that this server supports.
                subject_types_supported
                    REQUIRED. JSON array containing a list of the subject identifier types that this server supports. Valid types include pairwise and public.
                userinfo_signing_alg_values_supported
                    OPTIONAL. JSON array containing a list of the JWS [JWS] signing algorithms (alg values) [JWA] supported by the UserInfo Endpoint to
                    encode the Claims in a JWT [JWT].
                userinfo_encryption_alg_values_supported
                    OPTIONAL. JSON array containing a list of the JWE [JWE] encryption algorithms (alg values) [JWA] supported by the UserInfo Endpoint to
                    encode the Claims in a JWT [JWT].
                userinfo_encryption_enc_values_supported
                    OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) [JWA] supported by the UserInfo Endpoint to
                    encode the Claims in a JWT [JWT].
                id_token_signing_alg_values_supported
                    REQUIRED. JSON array containing a list of the JWS signing algorithms (alg values) supported by the Authorization Server for the
                    ID Token to encode the Claims in a JWT [JWT].
                id_token_encryption_alg_values_supported
                    OPTIONAL. JSON array containing a list of the JWE encryption algorithms (alg values) supported by the Authorization Server for the
                    ID Token to encode the Claims in a JWT [JWT].
                id_token_encryption_enc_values_supported
                    OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the Authorization Server for the
                    ID Token to encode the Claims in a JWT [JWT].
                request_object_signing_alg_values_supported
                    OPTIONAL. JSON array containing a list of the JWS signing algorithms (alg values) supported by the Authorization Server for
                    the Request Object described in Section 2.9 of OpenID Connect Messages 1.0 [OpenID.Messages]. These algorithms are used both when
                    the Request Object is passed by value (using the request parameter) and when it is passed by reference (using the request_uri parameter).
                    Servers SHOULD support none and RS256.
                request_object_encryption_alg_values_supported
                    OPTIONAL. JSON array containing a list of the JWE encryption algorithms (alg values) supported by the Authorization Server for
                    the Request Object described in Section 2.9 of OpenID Connect Messages 1.0 [OpenID.Messages]. These algorithms are used both when
                    the Request Object is passed by value and when it is passed by reference.
                request_object_encryption_enc_values_supported
                    OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the Authorization Server for
                    the Request Object described in Section 2.9 of OpenID Connect Messages 1.0 [OpenID.Messages]. These algorithms are used both when
                    the Request Object is passed by value and when it is passed by reference.
                token_endpoint_auth_methods_supported
                    OPTIONAL. JSON array containing a list of authentication methods supported by this Token Endpoint.
                    The options are client_secret_post, client_secret_basic, client_secret_jwt, and private_key_jwt,
                    as described in Section 2.2.1 of OpenID Connect Messages 1.0 [OpenID.Messages].
                    Other authentication methods MAY be defined by extensions.
                    If omitted, the default is client_secret_basic -- the HTTP Basic Authentication Scheme as specified in
                    Section 2.3.1 of OAuth 2.0 [RFC6749].
                token_endpoint_auth_signing_alg_values_supported
                    OPTIONAL. JSON array containing a list of the JWS signing algorithms (alg values) supported by the Token Endpoint for
                    the private_key_jwt and client_secret_jwt methods to encode the JWT [JWT]. Servers SHOULD support RS256.
                display_values_supported
                    OPTIONAL. JSON array containing a list of the display parameter values that the OpenID Provider supports.
                    These values are described in Section 2.1.1 of OpenID Connect Messages 1.0 [OpenID.Messages].
                claim_types_supported
                    OPTIONAL. JSON array containing a list of the Claim Types that the OpenID Provider supports.
                    These Claim Types are described in Section 2.6 of OpenID Connect Messages 1.0 [OpenID.Messages].
                    Values defined by this specification are normal, aggregated, and distributed.
                    If not specified, the implementation supports only normal Claims.
                claims_supported
                    RECOMMENDED. JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able to supply values for.
                    Note that for privacy or other reasons, this might not be an exhaustive list.
                service_documentation
                    OPTIONAL. URL of a page containing human-readable information that developers might want or need to know when using the OpenID Provider.
                    In particular, if the OpenID Provider does not support Dynamic Client Registration, then information on how to register Clients needs
                    to be provided in this documentation.
                claims_locales_supported
                    OPTIONAL. Languages and scripts supported for values in Claims being returned, represented as a JSON array of
                    BCP47 [RFC5646] language tag values. Not all languages and scripts are necessarily supported for all Claim values.
                ui_locales_supported
                    OPTIONAL. Languages and scripts supported for the user interface, represented as a JSON array of BCP47 [RFC5646] language tag values.
                claims_parameter_supported
                    OPTIONAL. Boolean value specifying whether the OP supports use of the claims parameter, with true indicating support.
                    If omitted, the default value is false.
                request_parameter_supported
                    OPTIONAL. Boolean value specifying whether the OP supports use of the request parameter, with true indicating support.
                    If omitted, the default value is false.
                request_uri_parameter_supported
                    OPTIONAL. Boolean value specifying whether the OP supports use of the request_uri parameter, with true indicating support.
                    If omitted, the default value is true.
                require_request_uri_registration
                    OPTIONAL. Boolean value specifying whether the OP requires any request_uri values used to be pre-registered using
                    the request_uris registration parameter. Pre-registration is REQUIRED when the value is true. If omitted, the default value is false.
                op_policy_uri
                    OPTIONAL. URL that the OpenID Provider provides to the person registering the Client to read about the OP's requirements on
                    how the Relying Party can use the data provided by the OP. The registration process SHOULD display this URL to the person registering
                    the Client if it is given.
                op_tos_uri
                    OPTIONAL. URL that the OpenID Provider provides to the person registering the Client to read about OpenID Provider's terms of service.
                    The registration process SHOULD display this URL to the person registering the Client if it is given.
             */

            var baseUrl = config.issuer

            if (!baseUrl.endsWith("/")) {
                logger.debug("Configured issuer doesn't end in /, adding for discovery: {}", baseUrl)
                baseUrl = "$baseUrl/"
            }

            signService.allSigningAlgsSupported
            listOf(JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512)

            val clientSymmetricAndAsymmetricSigningAlgs: Collection<JWSAlgorithm> = listOf(
                JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512,
                JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512,
                JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512,
                JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512
            )
            val clientSymmetricAndAsymmetricSigningAlgsWithNone: Collection<Algorithm> = listOf(
                JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512,
                JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512,
                JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512,
                JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512,
                Algorithm.NONE
            )
            val grantTypes =
                listOf("authorization_code", "implicit", "urn:ietf:params:oauth:grant-type:jwt-bearer", "client_credentials", "urn:ietf:params:oauth:grant_type:redelegate", "urn:ietf:params:oauth:grant-type:device_code", "refresh_token")

            val result = buildJsonObject {
                put("issuer", config.issuer)
                put("authorization_endpoint", baseUrl + "authorize")
                put("token_endpoint", "${baseUrl}token")
                put("userinfo_endpoint", "${baseUrl}userinfo")
                //check_session_iframe
                put("end_session_endpoint", baseUrl + "endsession")
                put("jwks_uri", "${baseUrl}jwk")
                put("registration_endpoint", baseUrl + "register")
                putJsonArray("scopes_supported") {
                    scopeService.toStrings(scopeService.unrestricted)?.let {
                        for(s in it) add(s)
                    }
                }
                putJsonArray("response_types_supported") {
                    add("code")
                    add("token")
                    // we don't support these yet: , "id_token", "id_token token"));
                }
                putJsonArray("grant_types_supported") {
                    addAll(grantTypes)
                }
                putJsonArray("subject_types_supported") {
                    addAll(listOf("public", "pairwise"))
                }
                putJsonArray("userinfo_signing_alg_values_supported") {
                    addAll(clientSymmetricAndAsymmetricSigningAlgs.map(toAlgorithmName))
                }

                putJsonArray("userinfo_encryption_alg_values_supported") {
                    addAll(encService.allEncryptionAlgsSupported.map(toAlgorithmName))
                }

                putJsonArray("userinfo_encryption_enc_values_supported") {
                    addAll(encService.allEncryptionEncsSupported.map(toAlgorithmName))
                }

                putJsonArray("id_token_signing_alg_values_supported") {
                    addAll(clientSymmetricAndAsymmetricSigningAlgsWithNone.map(toAlgorithmName))
                }

                putJsonArray("id_token_encryption_alg_values_supported") {
                    addAll(encService.allEncryptionAlgsSupported.map(toAlgorithmName))
                }

                putJsonArray("id_token_encryption_enc_values_supported") {
                    addAll(encService.allEncryptionEncsSupported.map(toAlgorithmName))
                }

                putJsonArray("request_object_signing_alg_values_supported") {
                    addAll(clientSymmetricAndAsymmetricSigningAlgs.map(toAlgorithmName))
                }

                putJsonArray("request_object_encryption_alg_values_supported") {
                    addAll(encService.allEncryptionAlgsSupported.map(toAlgorithmName))
                }

                putJsonArray("request_object_encryption_enc_values_supported") {
                    addAll(encService.allEncryptionEncsSupported.map(toAlgorithmName))
                }

                putJsonArray("token_endpoint_auth_methods_supported") {
                    addAll(listOf("client_secret_post", "client_secret_basic", "client_secret_jwt", "private_key_jwt", "none"))
                }

                putJsonArray("token_endpoint_auth_signing_alg_values_supported") {
                    addAll(clientSymmetricAndAsymmetricSigningAlgs.map(toAlgorithmName))
                }
                //display_types_supported
                putJsonArray("claim_types_supported") { addAll(listOf("normal")) }
                putJsonArray("claims_supported") {
                    addAll(listOf("sub", "name", "preferred_username", "given_name", "family_name", "middle_name", "nickname", "profile", "picture", "website", "gender", "zoneinfo", "locale", "updated_at", "birthdate", "email", "email_verified", "phone_number", "phone_number_verified", "address"))
                }
                put("service_documentation", baseUrl + "about")
                //claims_locales_supported
                //ui_locales_supported
                put("claims_parameter_supported", false)
                put("request_parameter_supported", true)
                put("request_uri_parameter_supported", false)
                put("require_request_uri_registration", false)
                put("op_policy_uri", "${baseUrl}about")
                put("op_tos_uri", "${baseUrl}about")

                put("introspection_endpoint", "${baseUrl}introspect") // token introspection endpoint for verifying tokens
                put("revocation_endpoint", "${baseUrl}revoke") // token revocation endpoint

                putJsonArray("code_challenge_methods_supported") { addAll(listOf(PKCEAlgorithm.plain.name, PKCEAlgorithm.S256.name)) }

                put("device_authorization_endpoint", "${baseUrl}devicecode")

            }

            // force json
            call.respondText(Json.encodeToString(result), ContentType.Application.Json)
        }
    }

    companion object {
        const val WELL_KNOWN_URL: String = ".well-known"
        const val OPENID_CONFIGURATION_URL: String = WELL_KNOWN_URL + "/openid-configuration"
        const val WEBFINGER_URL: String = WELL_KNOWN_URL + "/webfinger"

        /**
         * Logger for this class
         */
        private val logger = getLogger<DiscoveryEndpoint>()
    }
}
