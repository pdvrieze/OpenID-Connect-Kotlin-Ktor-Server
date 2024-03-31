package org.mitre.discovery.view

import com.google.gson.ExclusionStrategy
import com.google.gson.FieldAttributes
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import org.mitre.openid.connect.view.HttpCodeView
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.validation.BeanPropertyBindingResult
import org.springframework.web.servlet.view.AbstractView
import java.io.IOException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * @author jricher
 */
@Component("webfingerView")
class WebfingerView : AbstractView() {
    private val gson: Gson = GsonBuilder()
        .setExclusionStrategies(object : ExclusionStrategy {
            override fun shouldSkipField(f: FieldAttributes): Boolean {
                return false
            }

            override fun shouldSkipClass(clazz: Class<*>): Boolean {
                // skip the JPA binding wrapper
                return clazz == BeanPropertyBindingResult::class.java
            }
        })
        .serializeNulls()
        .setDateFormat("yyyy-MM-dd'T'HH:mm:ssZ")
        .create()

    override fun renderMergedOutputModel(
        model: Map<String, Any>,
        request: HttpServletRequest,
        response: HttpServletResponse
    ) {
        response.contentType = "application/jrd+json"


        var code = model[HttpCodeView.CODE] as HttpStatus?
        if (code == null) {
            code = HttpStatus.OK // default to 200
        }

        response.setStatus(code.value())

        try {
            val resource = model["resource"] as String?
            val issuer = model["issuer"] as String?

            val obj = JsonObject().apply {
                addProperty("subject", resource)

                val links = JsonArray().apply {
                    val link = JsonObject().apply {
                        addProperty("rel", "http://openid.net/specs/connect/1.0/issuer")
                        addProperty("href", issuer)
                    }
                    add(link)
                }

                add("links", links)
            }


            gson.toJson(obj, response.writer)
        } catch (e: IOException) {
            Companion.logger.error("IOException in JsonEntityView.java: ", e)
        }
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(WebfingerView::class.java)
    }
}
