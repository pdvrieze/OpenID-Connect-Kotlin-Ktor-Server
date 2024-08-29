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

import com.nimbusds.jose.jwk.JWKSet
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import org.mitre.util.getLogger
import java.text.ParseException
import javax.persistence.AttributeConverter
import javax.persistence.Converter

/**
 * @author jricher
 */
@Converter
class JWKSetStringConverter : AttributeConverter<JWKSet?, String?>, KSerializer<JWKSet> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("com.nimbusds.jose.jwk.JKWSet", PrimitiveKind.STRING)

    override fun convertToDatabaseColumn(attribute: JWKSet?): String? {
        return attribute?.toString()
    }

    override fun convertToEntityAttribute(dbData: String?): JWKSet? {
        return dbData?.let {
            try {
                JWKSet.parse(it)
            } catch (e: ParseException) {
                logger.error("Unable to parse JWK Set", e)
                throw e
            }
        }
    }

    override fun serialize(encoder: Encoder, value: JWKSet) {
        encoder.encodeString(value.toString())
    }

    override fun deserialize(decoder: Decoder): JWKSet {
        return JWKSet.parse(decoder.decodeString())
    }

    companion object {
        private val logger = getLogger<JWKSetStringConverter>()
    }
}
