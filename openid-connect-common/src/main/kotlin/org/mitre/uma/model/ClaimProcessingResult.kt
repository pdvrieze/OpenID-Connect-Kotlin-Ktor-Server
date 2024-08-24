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
package org.mitre.uma.model

/**
 * Data shuttle to return results of the claims processing service.
 *
 * @author jricher
 */
class ClaimProcessingResult {
    var isSatisfied: Boolean

    var unmatched: Collection<Claim>

    var matched: Policy?

    /**
     * Create an unmatched result. isSatisfied is false.
     */
    constructor(unmatched: Collection<Claim>) {
        this.isSatisfied = false
        this.unmatched = unmatched
        this.matched = null
    }

    /**
     * Create a matched result. isSatisfied is true.
     */
    constructor(matched: Policy) {
        this.isSatisfied = true
        this.matched = matched
        this.unmatched = emptyList()
    }
}
