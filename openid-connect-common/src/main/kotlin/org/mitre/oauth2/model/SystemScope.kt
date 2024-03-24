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

import javax.persistence.Basic
import javax.persistence.Column
import javax.persistence.Entity
import javax.persistence.GeneratedValue
import javax.persistence.GenerationType
import javax.persistence.Id
import javax.persistence.NamedQueries
import javax.persistence.NamedQuery
import javax.persistence.Table

/**
 * @author jricher
 */
@Entity
@Table(name = "system_scope")
@NamedQueries(NamedQuery(name = SystemScope.QUERY_ALL, query = "select s from SystemScope s ORDER BY s.id"), NamedQuery(name = SystemScope.QUERY_BY_VALUE, query = "select s from SystemScope s WHERE s.value = :" + SystemScope.PARAM_VALUE))
class SystemScope {
    @get:Column(name = "id")
    @get:GeneratedValue(strategy = GenerationType.IDENTITY)
    @get:Id
    var id: Long? = null

    @get:Column(name = "scope")
    @get:Basic
    var value: String? = null // scope value

    @get:Column(name = "description")
    @get:Basic
    var description: String? = null // human-readable description

    @get:Column(name = "icon")
    @get:Basic
    var icon: String? = null // class of the icon to display on the auth page

    @get:Column(name = "default_scope")
    @get:Basic
    var isDefaultScope: Boolean = false // is this a default scope for newly-registered clients?

    @get:Column(name = "restricted")
    @get:Basic
    var isRestricted: Boolean = false // is this scope restricted to admin-only registration access?

    /**
     * Make a blank system scope with no value
     */
    constructor()

    /**
     * Make a system scope with the given scope value
     */
    constructor(value: String?) {
        this.value = value
    }

    /* (non-Javadoc)
	 * @see java.lang.Object#hashCode()
	 */
    override fun hashCode(): Int {
        val prime = 31
        var result = 1
        result = prime * result + (if (isDefaultScope) 1231 else 1237)
        result = (prime * result
                + (if ((description == null)) 0 else description.hashCode()))
        result = prime * result + (if ((icon == null)) 0 else icon.hashCode())
        result = prime * result + (if ((id == null)) 0 else id.hashCode())
        result = prime * result + (if (isRestricted) 1231 else 1237)
        result = prime * result + (if ((value == null)) 0 else value.hashCode())
        return result
    }

    /* (non-Javadoc)
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other == null) {
            return false
        }
        if (javaClass != other.javaClass) {
            return false
        }
        other as SystemScope
        if (isDefaultScope != other.isDefaultScope) {
            return false
        }
        if (description == null) {
            if (other.description != null) {
                return false
            }
        } else if (description != other.description) {
            return false
        }
        if (icon == null) {
            if (other.icon != null) {
                return false
            }
        } else if (icon != other.icon) {
            return false
        }
        if (id == null) {
            if (other.id != null) {
                return false
            }
        } else if (id != other.id) {
            return false
        }
        if (isRestricted != other.isRestricted) {
            return false
        }
        if (value == null) {
            if (other.value != null) {
                return false
            }
        } else if (value != other.value) {
            return false
        }
        return true
    }

    /* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
    override fun toString(): String {
        return ("SystemScope [id=" + id + ", value=" + value + ", description="
                + description + ", icon=" + icon + ", defaultScope="
                + isDefaultScope + ", restricted=" + isRestricted + "]")
    }

    companion object {
        const val QUERY_BY_VALUE: String = "SystemScope.getByValue"
        const val QUERY_ALL: String = "SystemScope.findAll"

        const val PARAM_VALUE: String = "value"
    }
}
