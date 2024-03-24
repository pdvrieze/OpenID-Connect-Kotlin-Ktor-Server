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
package org.mitre.uma.model

import org.mitre.oauth2.model.RegisteredClient
import org.mitre.uma.model.convert.RegisteredClientStringConverter
import javax.persistence.Basic
import javax.persistence.Column
import javax.persistence.Convert
import javax.persistence.Entity
import javax.persistence.GeneratedValue
import javax.persistence.GenerationType
import javax.persistence.Id
import javax.persistence.Table

/**
 * @author jricher
 */
@Entity
@Table(name = "saved_registered_client")
class SavedRegisteredClient {
    @get:Column(name = "id")
    @get:GeneratedValue(strategy = GenerationType.IDENTITY)
    @get:Id
    var id: Long? = null

    @get:Column(name = "issuer")
    @get:Basic
    var issuer: String? = null

    @get:Convert(converter = RegisteredClientStringConverter::class)
    @get:Column(name = "registered_client")
    @get:Basic
    var registeredClient: RegisteredClient? = null
}
