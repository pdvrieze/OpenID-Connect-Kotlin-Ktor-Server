package org.mitre.discovery.view

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.mitre.openid.connect.service.MITREidDataService
import org.mitre.openid.connect.view.HttpCodeView
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.servlet.view.AbstractView
import java.io.IOException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * @author jricher
 */
@Component("webfingerView")
class WebfingerView : AbstractView() {

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

            val obj = buildJsonObject {
                put("subject", resource)
                putJsonArray("links") {
                    addJsonObject {
                        put("rel", "http://openid.net/specs/connect/1.0/issuer")
                        put("href", issuer)
                    }
                }
            }

            response.writer.append(MITREidDataService.json.encodeToString(obj))
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
