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

/**
 *
 * Simple view resolver to map JWK view names to appropriate beans
 *
 * @author jricher
 */
/*
class JwkViewResolver : ViewResolver, Ordered {
    var jwkViewName: String = "jwkKeyList"
    var jwk: View? = null

    private var order =
        Ordered.HIGHEST_PRECEDENCE // highest precedence, most specific -- avoids hitting the catch-all view resolvers

    */
/**
     * Map "jwkKeyList" to the jwk property on this bean.
     * Everything else returns null
     *//*

    @Throws(Exception::class)
    override fun resolveViewName(viewName: String?, locale: Locale): View? {
        return when (viewName) {
            null -> null
            jwkViewName -> jwk
            else -> null
        }
    }

    override fun getOrder(): Int {
        return order
    }

    fun setOrder(order: Int) {
        this.order = order
    }
}
*/
