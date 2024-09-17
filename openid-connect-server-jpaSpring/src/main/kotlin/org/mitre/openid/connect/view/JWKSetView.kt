package org.mitre.openid.connect.view

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import org.mitre.util.getLogger
import org.springframework.web.servlet.view.AbstractView
import java.io.IOException
import java.io.Writer
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * @author jricher
 */
class JWKSetView : AbstractView() {
    override fun renderMergedOutputModel(
        model: Map<String, Any>,
        request: HttpServletRequest,
        response: HttpServletResponse
    ) {
        //BiMap<String, PublicKey> keyMap = (BiMap<String, PublicKey>) model.get("keys");
        val keys = model["keys"] as Map<String, JWK>

        response.contentType = "application/json"



        val jwkSet = JWKSet(ArrayList(keys.values))

        try {
            val out: Writer = response.writer
            out.write(jwkSet.toString())
        } catch (e: IOException) {
            Companion.logger.error("IOException in JWKSetView.java: ", e)
        }
    }

    companion object {
        const val VIEWNAME: String = "jwkSet"

        /**
         * Logger for this class
         */
        private val logger = getLogger<JWKSetView>()
    }
}
