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
package org.mitre.openid.connect.client.keypublisher

import org.springframework.stereotype.Component
import org.springframework.web.servlet.mvc.condition.PatternsRequestCondition
import org.springframework.web.servlet.mvc.method.RequestMappingInfo
import org.springframework.web.servlet.mvc.method.RequestMappingInfoHandlerMapping
import java.lang.reflect.Method

/**
 * @author jricher
 */
@Component
class ClientKeyPublisherMapping : RequestMappingInfoHandlerMapping() {
    var jwkPublishUrl: String? = null

    override fun isHandler(beanType: Class<*>): Boolean {
        return beanType == ClientKeyPublisher::class.java
    }

    override fun getMappingForMethod(method: Method, handlerType: Class<*>?): RequestMappingInfo? {
        return if (method.name == "publishClientJwk" && jwkPublishUrl != null) {
            RequestMappingInfo(
                PatternsRequestCondition(arrayOf(jwkPublishUrl), urlPathHelper, pathMatcher, false, false),
                null,
                null,
                null,
                null,
                null,
                null
            )
        } else {
            null
        }
    }
}
