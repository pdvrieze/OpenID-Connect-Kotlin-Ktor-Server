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
package org.mitre.openid.connect.config

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.mitre.openid.connect.service.MITREidDataService
import org.mitre.util.asString
import org.mitre.util.getLogger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.support.AbstractMessageSource
import org.springframework.core.io.Resource
import org.springframework.stereotype.Component
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.io.InputStreamReader
import java.text.MessageFormat
import java.util.*

/**
 * @author jricher
 */
@Component
class JsonMessageSource : AbstractMessageSource() {
    lateinit var baseDirectory: Resource

    private val fallbackLocale = Locale("en") // US English is the fallback language

    private val languageMaps: MutableMap<Locale, List<JsonObject>?> = HashMap()

    @Autowired
    private lateinit var config: ConfigurationPropertiesBean

    public override fun resolveCode(code: String, locale: Locale): MessageFormat? {
        val value = getValue(code, getLanguageMap(locale))
                // if we haven't found anything, try the default locale
            ?: getValue(code, getLanguageMap(fallbackLocale))
            ?: return null // if it's still null, return null

        return MessageFormat(value, locale)
    }

    /**
     * Get a value from the set of maps, taking the first match in order
     */
    private fun getValue(code: String, langs: List<JsonObject>?): String? {
        if (langs == null) return null
        return langs.asSequence().mapNotNull { getValue(code, it) }.firstOrNull()
    }

    /**
     * Get a value from a single map
     */
    private fun getValue(code: String, lang: JsonObject?): String? {
        // if there's no language map, nothing to look up

        if (lang == null) return null

        var e: JsonElement = lang

        val parts = code.split('.')
        val it: Iterator<String> = parts.iterator()

        var value: String? = null

        while (it.hasNext()) {
            val p = it.next()
            if (e is JsonObject) {
                val o = e[p]
                if (o != null) {
                    e = o // found the next level
                    if (!it.hasNext()) {
                        // we've reached a leaf, grab it
                        if (e is JsonPrimitive) {
                            value = e.asString()
                        }
                    }
                } else {
                    // didn't find it, stop processing
                    break
                }
            } else {
                // didn't find it, stop processing
                break
            }
        }

        return value
    }


    private fun getLanguageMap(locale: Locale): List<JsonObject>? {
        if (!languageMaps.containsKey(locale)) {
            try {
                val set: MutableList<JsonObject> = ArrayList()
                for (namespace in config.languageNamespaces) {
                    // full locale string, e.g. "en_US"
                    var filename = "${locale.language}_${locale.country}${File.separator}$namespace.json"

                    var r: Resource = baseDirectory.createRelative(filename)

                    if (!r.exists()) {
                        // fallback to language only
                        myLogger.debug("Fallback locale to language only.")
                        filename = locale.language + File.separator + namespace + ".json"
                        r = baseDirectory.createRelative(filename)
                    }

                    myLogger.info("No locale loaded, trying to load from $r")

                    val obj = r.inputStream.use {
                        val reader = InputStreamReader(r.inputStream, "UTF-8")
                        MITREidDataService.json.parseToJsonElement(reader.readText()).jsonObject
                    }

                    set.add(obj)
                }
                languageMaps[locale] = set
            } catch (e: FileNotFoundException) {
                myLogger.info("Unable to load locale because no messages file was found for locale ${locale.displayName}")
                languageMaps[locale] = null
            } catch (e: SerializationException) {
                myLogger.error("Unable to load locale", e)
            } catch (e: IOException) {
                myLogger.error("Unable to load locale", e)
            }
        }

        return languageMaps[locale]
    }

    companion object {
        @JvmStatic
        private val myLogger = getLogger<JsonMessageSource>()
    }
}
