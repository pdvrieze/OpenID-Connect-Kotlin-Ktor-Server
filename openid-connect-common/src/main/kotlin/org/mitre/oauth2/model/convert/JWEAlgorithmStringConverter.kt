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

import com.nimbusds.jose.JWEAlgorithm
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import javax.persistence.AttributeConverter
import javax.persistence.Converter

@Converter
class JWEAlgorithmStringConverter : AttributeConverter<JWEAlgorithm?, String?>, KSerializer<JWEAlgorithm> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("com.nimbusds.jose.JWEAlgorithm", PrimitiveKind.STRING)

    override fun convertToDatabaseColumn(attribute: JWEAlgorithm?): String? {
        return attribute?.name
    }

    /* (non-Javadoc)
	 * @see javax.persistence.AttributeConverter#convertToEntityAttribute(java.lang.Object)
	 */
    override fun convertToEntityAttribute(dbData: String?): JWEAlgorithm? {
        return dbData?.let(JWEAlgorithm::parse)
    }

    override fun serialize(encoder: Encoder, value: JWEAlgorithm) {
        encoder.encodeString(value.name)
    }

    override fun deserialize(decoder: Decoder): JWEAlgorithm {
        return JWEAlgorithm.parse(decoder.decodeString())
    }
}
