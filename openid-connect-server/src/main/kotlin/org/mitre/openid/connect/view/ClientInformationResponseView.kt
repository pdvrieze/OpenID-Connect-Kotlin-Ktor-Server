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

import com.google.gson.Gson
import com.google.gson.JsonIOException
import org.mitre.oauth2.model.RegisteredClient
import org.mitre.openid.connect.ClientDetailsEntityJsonProcessor.serialize
import org.mitre.openid.connect.view.ClientInformationResponseView
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.stereotype.Component
import org.springframework.web.servlet.view.AbstractView
import java.io.IOException
import java.io.Writer
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
    // note that this won't serialize nulls by default
    private val gson = Gson()

    /* (non-Javadoc)
	 * @see org.springframework.web.servlet.view.AbstractView#renderMergedOutputModel(java.util.Map, javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */
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

        val o = serialize(c)

        try {
            val out: Writer = response.writer
            gson.toJson(o, out)
        } catch (e: JsonIOException) {
            Companion.logger.error("JsonIOException in ClientInformationResponseView.java: ", e)
        } catch (e: IOException) {
            Companion.logger.error("IOException in ClientInformationResponseView.java: ", e)
        }
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(ClientInformationResponseView::class.java)

        const val VIEWNAME: String = "clientInformationResponseView"
    }
}
