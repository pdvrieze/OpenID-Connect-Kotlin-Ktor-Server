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

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

/**
 * @author jricher
 */
@Serializable
data class Claim(
    val id: Long? = null,
    val name: String? = null,
    val friendlyName: String? = null,
    val claimType: String? = null,
    val value: JsonElement? = null,
    val claimTokenFormat: Set<String> = emptySet(),
    val issuer: Set<String> = emptySet(),
)
