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
package org.mitre.oauth2.model

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.Requirement

/**
 * @author jricher
 */
class PKCEAlgorithm : Algorithm {
    constructor(name: String?, req: Requirement?) : super(name, req)

    constructor(name: String?) : super(name, null)

    companion object {
        /**
         *
         */
        private const val serialVersionUID = 7752852583210088925L

        @JvmField
		val plain: PKCEAlgorithm = PKCEAlgorithm("plain", Requirement.REQUIRED)

        @JvmField
		val S256: PKCEAlgorithm = PKCEAlgorithm("S256", Requirement.OPTIONAL)

        @JvmStatic
		fun parse(s: String): PKCEAlgorithm {
            return when (s) {
                plain.name -> plain
                S256.name -> S256
                else -> PKCEAlgorithm(s)
            }
        }
    }
}
