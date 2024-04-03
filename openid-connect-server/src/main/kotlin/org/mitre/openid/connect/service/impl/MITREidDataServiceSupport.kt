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
package org.mitre.openid.connect.service.impl

import kotlinx.serialization.json.Json
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.format.annotation.DateTimeFormat
import org.springframework.format.datetime.DateFormatter
import java.text.ParseException
import java.time.Instant
import java.util.*

abstract class MITREidDataServiceSupport {
    private val dateFormatter = DateFormatter().apply {
        setIso(DateTimeFormat.ISO.DATE_TIME)
    }

    protected fun utcToInstant(value: String?): Instant? {
        if (value == null) return null

        try {
            return dateFormatter.parse(value, Locale.ENGLISH).toInstant()
        } catch (ex: ParseException) {
            logger.error("Unable to parse datetime {}", value, ex)
        }
        return null
    }

    protected fun utcToDate(value: String?): Date? {
        if (value == null) return null

        try {
            return dateFormatter.parse(value, Locale.ENGLISH)
        } catch (ex: ParseException) {
            logger.error("Unable to parse datetime {}", value, ex)
        }
        return null
    }

    protected fun toUTCString(value: Instant?): String? {
        if (value == null) return null

        return dateFormatter.print(Date.from(value), Locale.ENGLISH)
    }

    protected fun toUTCString(value: Date?): String? {
        if (value == null) return null

        return dateFormatter.print(value, Locale.ENGLISH)
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(MITREidDataServiceSupport::class.java)
        internal val json: Json = Json {
            ignoreUnknownKeys = true
            prettyPrint = true
        }
    }
}
