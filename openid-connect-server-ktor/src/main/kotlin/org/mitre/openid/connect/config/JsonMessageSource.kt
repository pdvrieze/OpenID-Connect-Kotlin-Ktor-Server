package org.mitre.openid.connect.config

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.mitre.openid.connect.service.MITREidDataService
import org.mitre.util.asString
import org.mitre.util.getLogger
import java.io.FileNotFoundException
import java.io.IOException
import java.io.InputStreamReader
import java.text.MessageFormat
import java.util.*

/**
 * @author jricher
 */
class JsonMessageSource(private val baseResource: String, private val config: ConfigurationPropertiesBean) :
    MessageSource {

    private val fallbackLocale = Locale("en") // US English is the fallback language

    private val languageMaps: MutableMap<Locale, List<JsonObject>?> = HashMap()

    override fun resolveCode(code: String, locales: List<Locale>): MessageFormat? {
        val (locale, languageMap) = (locales.asSequence() + sequenceOf(fallbackLocale)).mapNotNull { k -> getLanguageMap(k)?.let { k to it } }.firstOrNull()
            ?: return null
        val value = getValue(code, languageMap) ?: return null

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
        val baseResource = when {
            baseResource.endsWith('/') -> baseResource.substring(0, baseResource.length - 1)
            else -> baseResource
        }

        if (!languageMaps.containsKey(locale)) {
            try {
                val set: MutableList<JsonObject> = ArrayList()
                for (namespace in config.languageNamespaces) {
                    // full locale string, e.g. "en_US"
                    var filename = "${locale.language}_${locale.country}/$namespace.json"

                    var input = javaClass.getResourceAsStream("$baseResource/$filename")

                    if (input == null) {
                        // fallback to language only
                        myLogger.debug("Fallback locale to language only.")
                        filename = "${locale.language}/$namespace.json"
                        input = javaClass.getResourceAsStream("$baseResource/$filename")

                        if (input == null) {
                            languageMaps[locale] = null
                            continue // try next language
                        }
                    }

                    myLogger.info("No locale loaded, trying to load from $baseResource/$filename")

                    val obj = input.use { r ->
                        val reader = InputStreamReader(r, "UTF-8")
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
