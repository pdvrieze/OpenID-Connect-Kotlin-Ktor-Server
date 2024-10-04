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
package org.mitre.oauth2.model.convert

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.LocalGrantedAuthority

/**
 * @author jricher
 */
class SimpleGrantedAuthorityStringConverter : KSerializer<GrantedAuthority> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("org.springframework.security.core.authority.SimpleGrantedAuthority", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: GrantedAuthority) {
        encoder.encodeString(value.authority)
    }

    override fun deserialize(decoder: Decoder): GrantedAuthority {
        return LocalGrantedAuthority(decoder.decodeString())
    }
}
