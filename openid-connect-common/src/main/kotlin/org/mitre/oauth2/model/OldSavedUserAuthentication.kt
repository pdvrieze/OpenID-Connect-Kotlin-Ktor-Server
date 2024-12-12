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

/**
 * This class stands in for an original Authentication object.
 *
 * @author jricher
 */
class OldSavedUserAuthentication(
    name: String,
    id: Long? = null,
    authorities: Collection<GrantedAuthority> = emptyList(),
    authenticated: Boolean = false,
    sourceClass: String? = null,
) : OldAuthentication {
    var id: Long? = id

    override var name: String = name
        private set

    override var authorities: Set<GrantedAuthority> = authorities.toHashSet()
        private set

    override var isAuthenticated = authenticated
        private set

    var sourceClass: String? = sourceClass

    /**
     * Create a Saved Auth from an existing Auth token
     */
    constructor(src: OldAuthentication) : this(
        name = src.name,
        id = null,
        authorities = src.authorities,
        authenticated = src.isAuthenticated,
        // if we're copying in a saved auth, carry over the original class name
        sourceClass = when (src) {
            is OldSavedUserAuthentication -> src.sourceClass
            else -> src.javaClass.name
        },
    )

    companion object {
        private const val serialVersionUID = -1804249963940323488L

        fun from(src: OldAuthentication): OldSavedUserAuthentication {
            return src as? OldSavedUserAuthentication ?: OldSavedUserAuthentication(src)
        }
    }
}
