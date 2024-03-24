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

import org.mitre.oauth2.model.convert.SimpleGrantedAuthorityStringConverter
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import javax.persistence.Basic
import javax.persistence.CollectionTable
import javax.persistence.Column
import javax.persistence.Convert
import javax.persistence.ElementCollection
import javax.persistence.Entity
import javax.persistence.FetchType
import javax.persistence.GeneratedValue
import javax.persistence.GenerationType
import javax.persistence.Id
import javax.persistence.JoinColumn
import javax.persistence.Table
import javax.persistence.Transient

/**
 * This class stands in for an original Authentication object.
 *
 * @author jricher
 */
@Entity
@Table(name = "saved_user_auth")
class SavedUserAuthentication : Authentication {
    @get:Column(name = "id")
    @get:GeneratedValue(strategy = GenerationType.IDENTITY)
    @get:Id
    var id: Long? = null

    private var name: String? = null

    private var authorities: Collection<GrantedAuthority>? = null

    private var authenticated = false

    @get:Column(name = "source_class")
    @get:Basic
    var sourceClass: String? = null

    /**
     * Create a Saved Auth from an existing Auth token
     */
    constructor(src: Authentication) {
        setName(src.name)
        setAuthorities(HashSet(src.authorities))
        isAuthenticated = src.isAuthenticated

        if (src is SavedUserAuthentication) {
            // if we're copying in a saved auth, carry over the original class name
            sourceClass = src.sourceClass
        } else {
            sourceClass = src.javaClass.name
        }
    }

    /**
     * Create an empty saved auth
     */
    constructor()

    @Basic
    @Column(name = "name")
    override fun getName(): String {
        return name!!
    }

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "saved_user_auth_authority", joinColumns = [JoinColumn(name = "owner_id")])
    @Convert(converter = SimpleGrantedAuthorityStringConverter::class)
    @Column(name = "authority")
    override fun getAuthorities(): Collection<GrantedAuthority>? {
        return authorities
    }

    @Transient
    override fun getCredentials(): Any {
        return ""
    }

    @Transient
    override fun getDetails(): Any? {
        return null
    }

    @Transient
    override fun getPrincipal(): Any {
        return getName()
    }

    @Basic
    @Column(name = "authenticated")
    override fun isAuthenticated(): Boolean {
        return authenticated
    }

    @Throws(IllegalArgumentException::class)
    override fun setAuthenticated(isAuthenticated: Boolean) {
        this.authenticated = isAuthenticated
    }

    /**
     * @param name the name to set
     */
    fun setName(name: String?) {
        this.name = name
    }

    /**
     * @param authorities the authorities to set
     */
    fun setAuthorities(authorities: Collection<GrantedAuthority>?) {
        this.authorities = authorities
    }


    companion object {
        private const val serialVersionUID = -1804249963940323488L
    }
}
