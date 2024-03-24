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
package org.mitre.oauth2.model

import org.mitre.oauth2.model.convert.SerializableStringConverter
import org.mitre.oauth2.model.convert.SimpleGrantedAuthorityStringConverter
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.OAuth2Request
import java.io.Serializable
import javax.persistence.*

@Entity
@Table(name = "authentication_holder")
@NamedQueries(
    NamedQuery(name = AuthenticationHolderEntity.QUERY_ALL, query = "select a from AuthenticationHolderEntity a"), NamedQuery(
        name = AuthenticationHolderEntity.QUERY_GET_UNUSED, query = "select a from AuthenticationHolderEntity a where " +
                "a.id not in (select t.authenticationHolder.id from OAuth2AccessTokenEntity t) and " +
                "a.id not in (select r.authenticationHolder.id from OAuth2RefreshTokenEntity r) and " +
                "a.id not in (select c.authenticationHolder.id from AuthorizationCodeEntity c)"
    )
)
class AuthenticationHolderEntity {
    @get:Column(name = "id")
    @get:GeneratedValue(strategy = GenerationType.IDENTITY)
    @get:Id
    var id: Long? = null

    @get:JoinColumn(name = "user_auth_id")
    @get:OneToOne(cascade = [CascadeType.ALL])
    var userAuth: SavedUserAuthentication? = null

    @get:Column(name = "authority")
    @get:Convert(converter = SimpleGrantedAuthorityStringConverter::class)
    @get:CollectionTable(name = "authentication_holder_authority", joinColumns = [JoinColumn(name = "owner_id")])
    @get:ElementCollection(fetch = FetchType.EAGER)
    var authorities: Collection<GrantedAuthority>? = null

    @get:Column(name = "resource_id")
    @get:CollectionTable(name = "authentication_holder_resource_id", joinColumns = [JoinColumn(name = "owner_id")])
    @get:ElementCollection(fetch = FetchType.EAGER)
    var resourceIds: Set<String>? = null

    @get:Column(name = "approved")
    @get:Basic
    var isApproved: Boolean = false

    @get:Column(name = "redirect_uri")
    @get:Basic
    var redirectUri: String? = null

    @get:Column(name = "response_type")
    @get:CollectionTable(name = "authentication_holder_response_type", joinColumns = [JoinColumn(name = "owner_id")])
    @get:ElementCollection(fetch = FetchType.EAGER)
    var responseTypes: Set<String>? = null

    @get:Convert(converter = SerializableStringConverter::class)
    @get:MapKeyColumn(name = "extension")
    @get:Column(name = "val")
    @get:CollectionTable(name = "authentication_holder_extension", joinColumns = [JoinColumn(name = "owner_id")])
    @get:ElementCollection(fetch = FetchType.EAGER)
    var extensions: Map<String, Serializable>? = null

    @get:Column(name = "client_id")
    @get:Basic
    var clientId: String? = null

    @get:Column(name = "scope")
    @get:CollectionTable(name = "authentication_holder_scope", joinColumns = [JoinColumn(name = "owner_id")])
    @get:ElementCollection(fetch = FetchType.EAGER)
    var scope: Set<String>? = null

    @get:MapKeyColumn(name = "param")
    @get:Column(name = "val")
    @get:CollectionTable(name = "authentication_holder_request_parameter", joinColumns = [JoinColumn(name = "owner_id")])
    @get:ElementCollection(fetch = FetchType.EAGER)
    var requestParameters: Map<String, String>? = null

    @get:Transient
    var authentication: OAuth2Authentication
        get() =// TODO: memoize this
            OAuth2Authentication(createOAuth2Request(), userAuth)
        set(authentication) {
            // pull apart the request and save its bits

            val o2Request = authentication.oAuth2Request
            authorities = if (o2Request.authorities == null) null else HashSet(o2Request.authorities)
            clientId = o2Request.clientId
            extensions = if (o2Request.extensions == null) null else HashMap(o2Request.extensions)
            redirectUri = o2Request.redirectUri
            requestParameters = if (o2Request.requestParameters == null) null else HashMap(o2Request.requestParameters)
            resourceIds = if (o2Request.resourceIds == null) null else HashSet(o2Request.resourceIds)
            responseTypes = if (o2Request.responseTypes == null) null else HashSet(o2Request.responseTypes)
            scope = if (o2Request.scope == null) null else HashSet(o2Request.scope)
            isApproved = o2Request.isApproved

            if (authentication.userAuthentication != null) {
                this.userAuth = SavedUserAuthentication(authentication.userAuthentication)
            } else {
                this.userAuth = null
            }
        }

    /**
     */
    private fun createOAuth2Request(): OAuth2Request {
        return OAuth2Request(requestParameters, clientId, authorities, isApproved, scope, resourceIds, redirectUri, responseTypes, extensions)
    }


    companion object {
        const val QUERY_GET_UNUSED: String = "AuthenticationHolderEntity.getUnusedAuthenticationHolders"
        const val QUERY_ALL: String = "AuthenticationHolderEntity.getAll"
    }
}
