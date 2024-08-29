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

import org.mitre.util.getLogger
import java.io.Serializable
import java.util.*
import javax.persistence.AttributeConverter
import javax.persistence.Converter

/**
 * Translates a Serializable object of certain primitive types
 * into a String for storage in the database, for use with the
 * OAuth2Request extensions map.
 *
 * This class does allow some extension data to be lost.
 *
 * @author jricher
 */
@Converter
class SerializableStringConverter : AttributeConverter<Serializable?, String?> {
    override fun convertToDatabaseColumn(attribute: Serializable?): String? {
        return when (attribute) {
            null -> null
            is String -> attribute

            is Long -> attribute.toString()

            is Date -> attribute.time.toString()

            else -> {
                logger.warn("Dropping data from request: $attribute :: ${attribute.javaClass}")
                null
            }
        }
    }

    override fun convertToEntityAttribute(dbData: String?): Serializable? {
        return dbData
    }

    companion object {
        private val logger = getLogger<SerializableStringConverter>()
    }
}
