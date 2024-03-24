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

import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTParser
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.text.ParseException
import javax.persistence.AttributeConverter
import javax.persistence.Converter

/**
 * @author jricher
 */
@Converter
class JWTStringConverter : AttributeConverter<JWT?, String?> {
    override fun convertToDatabaseColumn(attribute: JWT?): String? {
        return attribute?.serialize()
    }

    /* (non-Javadoc)
	 * @see javax.persistence.AttributeConverter#convertToEntityAttribute(java.lang.Object)
	 */
    override fun convertToEntityAttribute(dbData: String?): JWT? {
        return dbData?.let {
            try { JWTParser.parse(it) } catch (e: ParseException) {
                logger.error("Unable to parse JWT", e)
                null
            }
        }
    }

    companion object {
        var logger: Logger = LoggerFactory.getLogger(JWTStringConverter::class.java)
    }
}
