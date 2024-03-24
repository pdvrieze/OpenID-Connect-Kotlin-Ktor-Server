/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
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
package org.mitre.oauth2.model

object RegisteredClientFields {
    const val SOFTWARE_ID: String = "software_id"
    const val SOFTWARE_VERSION: String = "software_version"
    const val SOFTWARE_STATEMENT: String = "software_statement"
    const val CLAIMS_REDIRECT_URIS: String = "claims_redirect_uris"
    const val CLIENT_SECRET_EXPIRES_AT: String = "client_secret_expires_at"
    const val CLIENT_ID_ISSUED_AT: String = "client_id_issued_at"
    const val REGISTRATION_CLIENT_URI: String = "registration_client_uri"
    const val REGISTRATION_ACCESS_TOKEN: String = "registration_access_token"
    const val REQUEST_URIS: String = "request_uris"
    const val POST_LOGOUT_REDIRECT_URIS: String = "post_logout_redirect_uris"
    const val INITIATE_LOGIN_URI: String = "initiate_login_uri"
    const val DEFAULT_ACR_VALUES: String = "default_acr_values"
    const val REQUIRE_AUTH_TIME: String = "require_auth_time"
    const val DEFAULT_MAX_AGE: String = "default_max_age"
    const val TOKEN_ENDPOINT_AUTH_SIGNING_ALG: String = "token_endpoint_auth_signing_alg"
    const val ID_TOKEN_ENCRYPTED_RESPONSE_ENC: String = "id_token_encrypted_response_enc"
    const val ID_TOKEN_ENCRYPTED_RESPONSE_ALG: String = "id_token_encrypted_response_alg"
    const val ID_TOKEN_SIGNED_RESPONSE_ALG: String = "id_token_signed_response_alg"
    const val USERINFO_ENCRYPTED_RESPONSE_ENC: String = "userinfo_encrypted_response_enc"
    const val USERINFO_ENCRYPTED_RESPONSE_ALG: String = "userinfo_encrypted_response_alg"
    const val USERINFO_SIGNED_RESPONSE_ALG: String = "userinfo_signed_response_alg"
    const val REQUEST_OBJECT_SIGNING_ALG: String = "request_object_signing_alg"
    const val SUBJECT_TYPE: String = "subject_type"
    const val SECTOR_IDENTIFIER_URI: String = "sector_identifier_uri"
    const val APPLICATION_TYPE: String = "application_type"
    const val JWKS_URI: String = "jwks_uri"
    const val JWKS: String = "jwks"
    const val SCOPE_SEPARATOR: String = " "
    const val POLICY_URI: String = "policy_uri"
    const val RESPONSE_TYPES: String = "response_types"
    const val GRANT_TYPES: String = "grant_types"
    const val SCOPE: String = "scope"
    const val TOKEN_ENDPOINT_AUTH_METHOD: String = "token_endpoint_auth_method"
    const val TOS_URI: String = "tos_uri"
    const val CONTACTS: String = "contacts"
    const val LOGO_URI: String = "logo_uri"
    const val CLIENT_URI: String = "client_uri"
    const val CLIENT_NAME: String = "client_name"
    const val REDIRECT_URIS: String = "redirect_uris"
    const val CLIENT_SECRET: String = "client_secret"
    const val CLIENT_ID: String = "client_id"
    const val CODE_CHALLENGE_METHOD: String = "code_challenge_method"
}
