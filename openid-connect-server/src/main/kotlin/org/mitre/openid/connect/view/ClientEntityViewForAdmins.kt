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
package org.mitre.openid.connect.view

import com.google.gson.ExclusionStrategy
import com.google.gson.FieldAttributes
import org.springframework.stereotype.Component
import org.springframework.validation.BeanPropertyBindingResult

/**
 *
 * View bean for full view of client entity, for admins.
 *
 * @see ClientEntityViewForUsers
 *
 * @author jricher
 */
@Component(ClientEntityViewForAdmins.VIEWNAME)
class ClientEntityViewForAdmins : AbstractClientEntityView() {
    private val blacklistedFields: Set<String> = hashSetOf("additionalInformation")


    override val exclusionStrategy: ExclusionStrategy
        get() {
            return object : ExclusionStrategy {
                override fun shouldSkipField(f: FieldAttributes): Boolean {
                    return f.name in blacklistedFields
                }

                override fun shouldSkipClass(clazz: Class<*>): Boolean {
                    // skip the JPA binding wrapper
                    return clazz == BeanPropertyBindingResult::class.java
                }
            }
        }

    companion object {
        const val VIEWNAME: String = "clientEntityViewAdmins"
    }
}
