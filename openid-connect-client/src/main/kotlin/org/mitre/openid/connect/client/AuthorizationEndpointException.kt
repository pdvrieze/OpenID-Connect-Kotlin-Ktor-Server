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
package org.mitre.openid.connect.client

class AuthorizationEndpointException(val error: String, val errorDescription: String?, val errorURI: String?) :
    AuthenticationServiceException("Error from Authorization Endpoint: $error $errorDescription $errorURI") {

    override fun toString(): String {
        return "AuthorizationEndpointException [error=$error, errorDescription=$errorDescription, errorURI=$errorURI]"
    }

    companion object {
        private const val serialVersionUID = 6953119789654778380L
    }
}
