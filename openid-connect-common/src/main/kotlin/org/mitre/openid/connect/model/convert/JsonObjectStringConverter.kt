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
package org.mitre.openid.connect.model.convert

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.mitre.openid.connect.service.MITREidDataService.Companion.json
import javax.persistence.AttributeConverter
import javax.persistence.Converter

/**
 * @author jricher
 */
@Converter
class JsonObjectStringConverter : AttributeConverter<JsonObject?, String?> {
    override fun convertToDatabaseColumn(attribute: JsonObject?): String? {
        return attribute?.let { json.encodeToString(it) }
    }

    /* (non-Javadoc)
	 * @see javax.persistence.AttributeConverter#convertToEntityAttribute(java.lang.Object)
	 */
    override fun convertToEntityAttribute(dbData: String?): JsonObject? {
        return when {
            !dbData.isNullOrEmpty() -> json.parseToJsonElement(dbData).jsonObject
            else -> null
        }
    }
}
