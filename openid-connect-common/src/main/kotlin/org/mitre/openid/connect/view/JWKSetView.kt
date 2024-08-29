/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
 *
 * Portions copyright 2011-2013 The MITRE Corporation
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
package org.mitre.openid.connect.view

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import org.mitre.util.getLogger
import org.springframework.http.MediaType
import org.springframework.stereotype.Component
import org.springframework.web.servlet.view.AbstractView
import java.io.IOException
import java.io.Writer
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * @author jricher
 */
@Component(JWKSetView.VIEWNAME)
class JWKSetView : AbstractView() {
    override fun renderMergedOutputModel(
        model: Map<String, Any>,
        request: HttpServletRequest,
        response: HttpServletResponse
    ) {
        //BiMap<String, PublicKey> keyMap = (BiMap<String, PublicKey>) model.get("keys");
        val keys = model["keys"] as Map<String, JWK>

        response.contentType = MediaType.APPLICATION_JSON_VALUE



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
