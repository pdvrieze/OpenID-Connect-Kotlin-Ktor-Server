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
package org.mitre.openid.connect.config

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm

/**
 *
 * Container class for a client's view of a server's configuration
 *
 *
 *
 *
 * @property op_policy_uri
 *
 * @property op_tos_uri
 *
 *
 * @author nemonik, jricher
 */
class ServerConfiguration {
    /**
     * OPTIONAL. URL of the OP's Authentication and Authorization Endpoint [OpenID.Messages].
     */
    var authorizationEndpointUri: String? = null

    /**
     * OPTIONAL. URL of the OP's OAuth 2.0 Token Endpoint [OpenID.Messages].
     */
    var tokenEndpointUri: String? = null

    /**
     * RECOMMENDED. URL of the OP's Dynamic Client Registration Endpoint [OpenID.Registration].
     */
    var registrationEndpointUri: String? = null

    /**
     * REQUIRED | URL using the https scheme with no query or fragment component that the OP asserts as its Issuer
     * Identifier
     */
    var issuer: String? = null

    /**
     * REQUIRED. URL of the OP's JSON Web Key Set [JWK] document. This contains the signing key(s) the Client uses to
     * validate signatures from the OP. The JWK Set MAY also contain the Server's encryption key(s), which are used by
     * Clients to encrypt requests to the Server. When both signing and encryption keys are made available, a use (Key
     * Use) parameter value is REQUIRED for all keys in the document to indicate each key's intended usage.
     */
    lateinit var jwksUri: String

    /**
     * RECOMMENDED. URL of the OP's UserInfo Endpoint [OpenID.Messages]. This URL MUST use the
     * https scheme and MAY contain port, path, and query parameter components.
     */
    var userInfoUri: String? = null

    var introspectionEndpointUri: String? = null

    var revocationEndpointUri: String? = null

    /**
     * OPTIONAL. URL of an OP endpoint that provides a page to support cross-origin communications for session state
     * information with the RP Client, using the HTML5 postMessage API. The page is loaded from an invisible iframe
     * embedded in an RP page so that it can run in the OP's security context. See [OpenID.Session].
     */
    var checkSessionIframe: String? = null

    /**
     * OPTIONAL. URL of the OP's endpoint that initiates logging out the End-User. See [OpenID.Session].
     */
    var endSessionEndpoint: String? = null

    /**
     * RECOMMENDED. JSON array containing a list of the OAuth 2.0 [RFC6749] scope values that this server
     */
    var scopesSupported: List<String>? = null

    /**
     * REQUIRED. JSON array containing a list of the OAuth 2.0 response_type values that this server supports. The
     * server MUST support the code, id_token, and the token id_token response type values.
     */
    var responseTypesSupported: List<String> = emptyList()

    /**
     * OPTIONAL. JSON array containing a list of the OAuth 2.0 grant type values that this server supports. The server
     * MUST support the authorization_code and implicit grant type values and MAY support the
     * urn:ietf:params:oauth:grant-type:jwt-bearer grant type defined in OAuth JWT Bearer Token Profiles [OAuth.JWT]. If
     * omitted, the default value is ["authorization_code", "implicit"].
     */
    var grantTypesSupported: List<String>? = null

    /**
     * OPTIONAL. JSON array containing a list of the Authentication Context Class References that this server supports.
     */
    var acrValuesSupported: List<String>? = null

    /**
     * REQUIRED. JSON array containing a list of the subject identifier types that this server supports. Valid types
     * include pairwise and public.
     */
    var subjectTypesSupported: List<String> = emptyList()

    /**
     * OPTIONAL. JSON array containing a list of the JWS [JWS] signing algorithms (alg values) [JWA] supported by the
     * UserInfo Endpoint to encode the Claims in a JWT [JWT].
     */
    var userinfoSigningAlgValuesSupported: List<JWSAlgorithm>? = null

    /**
     * OPTIONAL. JSON array containing a list of the JWE [JWE] encryption algorithms (alg values) [JWA] supported by the
     * UserInfo Endpoint to encode the Claims in a JWT [JWT].
     */
    var userinfoEncryptionAlgValuesSupported: List<JWEAlgorithm>? = null

    /**
     * OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) [JWA] supported by the
     * UserInfo Endpoint to encode the Claims in a JWT [JWT].
     */
    var userinfoEncryptionEncValuesSupported: List<EncryptionMethod>? = null

    /**
     * REQUIRED. JSON array containing a list of the JWS signing algorithms (alg values) supported by the Authorization
     * Server for the ID Token to encode the Claims in a JWT [JWT].
     */
    var idTokenSigningAlgValuesSupported: List<JWSAlgorithm> = emptyList()

    /**
     * OPTIONAL. JSON array containing a list of the JWE encryption algorithms (alg values) supported by the
     * Authorization Server for the ID Token to encode the Claims in a JWT [JWT].
     */
    var idTokenEncryptionAlgValuesSupported: List<JWEAlgorithm>? = null

    /**
     * OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the
     * Authorization Server for the ID Token to encode the Claims in a JWT [JWT].
     */
    var idTokenEncryptionEncValuesSupported: List<EncryptionMethod>? = null

    /**
     * OPTIONAL. JSON array containing a list of the JWS signing algorithms (alg values) supported by the Authorization
     * Server for the Request Object described in Section 2.9 of OpenID Connect Messages 1.0. [OpenID.Messages]. These
     * algorithms are used both when the Request Object is passed by value (using the request parameter) and when it is
     * passed by reference (using the request_uri parameter). Servers SHOULD support none and RS256.
     */
    var requestObjectSigningAlgValuesSupported: List<JWSAlgorithm>? = null

    /**
     * OPTIONAL. JSON array containing a list of the JWE encryption algorithms (alg values) supported by the
     * Authorization Server for the Request Object described in Section 2.9 of OpenID Connect Messages 1.0
     * [OpenID.Messages]. These algorithms are used both when the Request Object is passed by value and when it is
     * passed by reference.
     */
    var requestObjectEncryptionAlgValuesSupported: List<JWEAlgorithm>? = null

    /**
     * OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the
     * Authorization Server for the Request Object described in Section 2.9 of OpenID Connect Messages 1.0
     * [OpenID.Messages]. These algorithms are used both when the Request Object is passed by value and when it is
     * passed by reference.
     */
    var requestObjectEncryptionEncValuesSupported: List<EncryptionMethod>? = null

    /**
     *  OPTIONAL. JSON array containing a list of authentication methods supported by this Token Endpoint. The options
     *  are client_secret_post, client_secret_basic, client_secret_jwt, and private_key_jwt, as described in Section
     *  2.2.1 of OpenID Connect Messages 1.0 [OpenID.Messages]. Other authentication methods MAY be defined by
     *  extensions. If omitted, the default is client_secret_basic -- the HTTP Basic Authentication Scheme as specified
     *  in Section 2.3.1 of OAuth 2.0 [RFC6749].
     */
    var tokenEndpointAuthMethodsSupported: List<String>? = null

    /**
     * OPTIONAL. JSON array containing a list of the JWS signing algorithms (alg values) supported by the Token Endpoint
     * for the private_key_jwt and client_secret_jwt methods to encode the JWT [JWT]. Servers SHOULD support RS256.
     */
    var tokenEndpointAuthSigningAlgValuesSupported: List<JWSAlgorithm>? = null

    /**
     * OPTIONAL. JSON array containing a list of the display parameter values that the OpenID Provider supports. These
     * values are described in Section 2.1.1 of OpenID Connect Messages 1.0 [OpenID.Messages].
     */
    var displayValuesSupported: List<String>? = null

    /**
     * OPTIONAL. JSON array containing a list of the Claim Types that the OpenID Provider supports. These Claim Types
     * are described in Section 2.6 of OpenID Connect Messages 1.0 [OpenID.Messages]. Values defined by this
     * specification are normal, aggregated, and distributed. If not specified, the implementation supports only normal
     * Claims.
     */
    var claimTypesSupported: List<String>? = null

    /**
     * RECOMMENDED. JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able
     * to supply values for. Note that for privacy or other reasons, this might not be an exhaustive list.
     */
    var claimsSupported: List<String>? = null

    /**
     * OPTIONAL. URL of a page containing human-readable information that developers might want or need to know when
     * using the OpenID Provider. In particular, if the OpenID Provider does not support Dynamic Client Registration,
     * then information on how to register Clients needs to be provided in this documentation.
     */
    var serviceDocumentation: String? = null

    /**
     * OPTIONAL. Languages and scripts supported for values in Claims being returned, represented as a JSON array of
     * BCP47 [RFC5646] language tag values. Not all languages and scripts are necessarily supported for all Claim
     * values.
     */
    var claimsLocalesSupported: List<String>? = null

    /**
     * OPTIONAL. Languages and scripts supported for the user interface, represented as a JSON array of BCP47 [RFC5646]
     * language tag values.
     */
    var uiLocalesSupported: List<String>? = null

    /**
     * OPTIONAL. Boolean value specifying whether the OP supports use of the claims parameter, with true indicating
     * support. If omitted, the default value is false.
     */
    var claimsParameterSupported: Boolean = false

    /**
     * OPTIONAL. Boolean value specifying whether the OP supports use of the request parameter, with true indicating
     * support. If omitted, the default value is false.
     */
    var requestParameterSupported: Boolean = false

    /**
     * OPTIONAL. Boolean value specifying whether the OP supports use of the request_uri parameter, with true indicating
     * support. If omitted, the default value is `true`.
     */
    var requestUriParameterSupported: Boolean = true

    /**
     * OPTIONAL. Boolean value specifying whether the OP requires any request_uri values used to be pre-registered using
     * the request_uris registration parameter. Pre-registration is REQUIRED when the value is `true`. If omitted, the
     * default value is `false`.
     */
    var requireRequestUriRegistration: Boolean = false

    /**
     * OPTIONAL. URL that the OpenID Provider provides to the person registering the Client to read about the OP's
     * requirements on how the Relying Party can use the data provided by the OP. The registration process SHOULD
     * display this URL to the person registering the Client if it is given.
     */
    var opPolicyUri: String? = null

    /**
     * OPTIONAL. URL that the OpenID Provider provides to the person registering the Client to read about OpenID
     * Provider's terms of service. The registration process SHOULD display this URL to the person registering the
     * Client if it is given.
     */
    var opTosUri: String? = null

    //
    // extensions to the discoverable methods
    //
    // how do we send the access token to the userinfo endpoint?
    var userInfoTokenMethod: UserInfoTokenMethod? = null

    enum class UserInfoTokenMethod {
        HEADER,
        FORM,
        QUERY
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ServerConfiguration

        if (authorizationEndpointUri != other.authorizationEndpointUri) return false
        if (tokenEndpointUri != other.tokenEndpointUri) return false
        if (registrationEndpointUri != other.registrationEndpointUri) return false
        if (issuer != other.issuer) return false
        if (jwksUri != other.jwksUri) return false
        if (userInfoUri != other.userInfoUri) return false
        if (introspectionEndpointUri != other.introspectionEndpointUri) return false
        if (revocationEndpointUri != other.revocationEndpointUri) return false
        if (checkSessionIframe != other.checkSessionIframe) return false
        if (endSessionEndpoint != other.endSessionEndpoint) return false
        if (scopesSupported != other.scopesSupported) return false
        if (responseTypesSupported != other.responseTypesSupported) return false
        if (grantTypesSupported != other.grantTypesSupported) return false
        if (acrValuesSupported != other.acrValuesSupported) return false
        if (subjectTypesSupported != other.subjectTypesSupported) return false
        if (userinfoSigningAlgValuesSupported != other.userinfoSigningAlgValuesSupported) return false
        if (userinfoEncryptionAlgValuesSupported != other.userinfoEncryptionAlgValuesSupported) return false
        if (userinfoEncryptionEncValuesSupported != other.userinfoEncryptionEncValuesSupported) return false
        if (idTokenSigningAlgValuesSupported != other.idTokenSigningAlgValuesSupported) return false
        if (idTokenEncryptionAlgValuesSupported != other.idTokenEncryptionAlgValuesSupported) return false
        if (idTokenEncryptionEncValuesSupported != other.idTokenEncryptionEncValuesSupported) return false
        if (requestObjectSigningAlgValuesSupported != other.requestObjectSigningAlgValuesSupported) return false
        if (requestObjectEncryptionAlgValuesSupported != other.requestObjectEncryptionAlgValuesSupported) return false
        if (requestObjectEncryptionEncValuesSupported != other.requestObjectEncryptionEncValuesSupported) return false
        if (tokenEndpointAuthMethodsSupported != other.tokenEndpointAuthMethodsSupported) return false
        if (tokenEndpointAuthSigningAlgValuesSupported != other.tokenEndpointAuthSigningAlgValuesSupported) return false
        if (displayValuesSupported != other.displayValuesSupported) return false
        if (claimTypesSupported != other.claimTypesSupported) return false
        if (claimsSupported != other.claimsSupported) return false
        if (serviceDocumentation != other.serviceDocumentation) return false
        if (claimsLocalesSupported != other.claimsLocalesSupported) return false
        if (uiLocalesSupported != other.uiLocalesSupported) return false
        if (claimsParameterSupported != other.claimsParameterSupported) return false
        if (requestParameterSupported != other.requestParameterSupported) return false
        if (requestUriParameterSupported != other.requestUriParameterSupported) return false
        if (requireRequestUriRegistration != other.requireRequestUriRegistration) return false
        if (opPolicyUri != other.opPolicyUri) return false
        if (opTosUri != other.opTosUri) return false
        if (userInfoTokenMethod != other.userInfoTokenMethod) return false

        return true
    }

    override fun hashCode(): Int {
        var result = authorizationEndpointUri?.hashCode() ?: 0
        result = 31 * result + (tokenEndpointUri?.hashCode() ?: 0)
        result = 31 * result + (registrationEndpointUri?.hashCode() ?: 0)
        result = 31 * result + issuer.hashCode()
        result = 31 * result + jwksUri.hashCode()
        result = 31 * result + (userInfoUri?.hashCode() ?: 0)
        result = 31 * result + (introspectionEndpointUri?.hashCode() ?: 0)
        result = 31 * result + (revocationEndpointUri?.hashCode() ?: 0)
        result = 31 * result + (checkSessionIframe?.hashCode() ?: 0)
        result = 31 * result + (endSessionEndpoint?.hashCode() ?: 0)
        result = 31 * result + (scopesSupported?.hashCode() ?: 0)
        result = 31 * result + responseTypesSupported.hashCode()
        result = 31 * result + (grantTypesSupported?.hashCode() ?: 0)
        result = 31 * result + (acrValuesSupported?.hashCode() ?: 0)
        result = 31 * result + subjectTypesSupported.hashCode()
        result = 31 * result + (userinfoSigningAlgValuesSupported?.hashCode() ?: 0)
        result = 31 * result + (userinfoEncryptionAlgValuesSupported?.hashCode() ?: 0)
        result = 31 * result + (userinfoEncryptionEncValuesSupported?.hashCode() ?: 0)
        result = 31 * result + idTokenSigningAlgValuesSupported.hashCode()
        result = 31 * result + (idTokenEncryptionAlgValuesSupported?.hashCode() ?: 0)
        result = 31 * result + (idTokenEncryptionEncValuesSupported?.hashCode() ?: 0)
        result = 31 * result + (requestObjectSigningAlgValuesSupported?.hashCode() ?: 0)
        result = 31 * result + (requestObjectEncryptionAlgValuesSupported?.hashCode() ?: 0)
        result = 31 * result + (requestObjectEncryptionEncValuesSupported?.hashCode() ?: 0)
        result = 31 * result + (tokenEndpointAuthMethodsSupported?.hashCode() ?: 0)
        result = 31 * result + (tokenEndpointAuthSigningAlgValuesSupported?.hashCode() ?: 0)
        result = 31 * result + (displayValuesSupported?.hashCode() ?: 0)
        result = 31 * result + (claimTypesSupported?.hashCode() ?: 0)
        result = 31 * result + (claimsSupported?.hashCode() ?: 0)
        result = 31 * result + (serviceDocumentation?.hashCode() ?: 0)
        result = 31 * result + (claimsLocalesSupported?.hashCode() ?: 0)
        result = 31 * result + (uiLocalesSupported?.hashCode() ?: 0)
        result = 31 * result + claimsParameterSupported.hashCode()
        result = 31 * result + requestParameterSupported.hashCode()
        result = 31 * result + requestUriParameterSupported.hashCode()
        result = 31 * result + requireRequestUriRegistration.hashCode()
        result = 31 * result + (opPolicyUri?.hashCode() ?: 0)
        result = 31 * result + (opTosUri?.hashCode() ?: 0)
        result = 31 * result + (userInfoTokenMethod?.hashCode() ?: 0)
        return result
    }

}
