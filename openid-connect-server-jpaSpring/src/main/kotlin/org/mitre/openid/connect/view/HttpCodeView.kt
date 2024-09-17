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

import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.servlet.view.AbstractView
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * An empty view that simply returns an HTTP code set in the model
 * @author jricher
 */
@Component(HttpCodeView.VIEWNAME)
class HttpCodeView : AbstractView() {
    override fun renderMergedOutputModel(
        model: Map<String, Any>,
        request: HttpServletRequest,
        response: HttpServletResponse
    ) {
        val code = (model[CODE] as HttpStatus?) ?: HttpStatus.OK

        response.setStatus(code.value())
    }

    companion object {
        const val VIEWNAME: String = "httpCodeView"

        const val CODE: String = "code"
    }
}
