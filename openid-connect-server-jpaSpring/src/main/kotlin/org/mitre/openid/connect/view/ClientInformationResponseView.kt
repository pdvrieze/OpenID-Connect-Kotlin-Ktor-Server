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

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToStream
import org.mitre.oauth2.model.RegisteredClient
import org.mitre.util.getLogger
import org.mitre.util.oidJson
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.stereotype.Component
import org.springframework.web.servlet.view.AbstractView
import java.io.IOException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 *
 * Provides representation of a client's registration metadata, to be shown from the dynamic registration endpoint
 * on the client_register and rotate_secret operations.
 *
 * @author jricher
 */
@Component(ClientInformationResponseView.VIEWNAME)
class ClientInformationResponseView : AbstractView() {

    /* (non-Javadoc)
	 * @see org.springframework.web.servlet.view.AbstractView#renderMergedOutputModel(java.util.Map, javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */
    @OptIn(ExperimentalSerializationApi::class)
    override fun renderMergedOutputModel(
        model: Map<String, Any>,
        request: HttpServletRequest,
        response: HttpServletResponse
    ) {
        response.contentType = MediaType.APPLICATION_JSON_VALUE

        val c = model["client"] as RegisteredClient

        //OAuth2AccessTokenEntity token = (OAuth2AccessTokenEntity) model.get("token");
        //String uri = (String)model.get("uri"); //request.getRequestURL() + "/" + c.getClientId();
        val code = (model[HttpCodeView.CODE] as HttpStatus?) ?: HttpStatus.OK

        response.setStatus(code.value())

        try {
            oidJson.encodeToStream(c, response.outputStream)
//            val out: Writer = response.writer
//            gson.toJson(o, out)
        } catch (e: SerializationException) {
            Companion.logger.error("SerializationException in ClientInformationResponseView.java: ", e)
        } catch (e: IOException) {
            Companion.logger.error("IOException in ClientInformationResponseView.java: ", e)
        }
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<ClientInformationResponseView>()

        const val VIEWNAME: String = "clientInformationResponseView"
    }
}
