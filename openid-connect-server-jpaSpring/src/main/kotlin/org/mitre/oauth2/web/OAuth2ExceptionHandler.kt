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
package org.mitre.oauth2.web

import org.mitre.util.getLogger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.ResponseEntity
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler

/**
 * Controller helper that handles OAuth2 exceptions and propagates them as JSON errors.
 *
 * @author jricher
 */
@ControllerAdvice
class OAuth2ExceptionHandler {
    @Autowired
    private lateinit var providerExceptionHandler: WebResponseExceptionTranslator

    @ExceptionHandler(OAuth2Exception::class)
    @Throws(Exception::class)
    fun handleException(e: Exception): ResponseEntity<OAuth2Exception> {
        logger.info("Handling error: " + e.javaClass.simpleName + ", " + e.message)
        return providerExceptionHandler.translate(e)
    }

    companion object {
        private val logger = getLogger<OAuth2ExceptionHandler>()
    }
}
