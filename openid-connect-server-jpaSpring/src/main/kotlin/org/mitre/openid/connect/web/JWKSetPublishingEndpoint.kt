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
package org.mitre.openid.connect.web

import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.RequestMapping

@Controller
class JWKSetPublishingEndpoint {
    @Autowired
    lateinit var jwtService: JWTSigningAndValidationService

    @RequestMapping(value = ["/" + URL], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun getJwk(m: Model): String {
        // map from key id to key

        val keys = jwtService.allPublicKeys

        // TODO: check if keys are empty, return a 404 here or just an empty list?
        m.addAttribute("keys", keys)

        return org.mitre.openid.connect.view.JWKSetView.VIEWNAME
    }

    companion object {
        const val URL: String = "jwk"
    }
}
