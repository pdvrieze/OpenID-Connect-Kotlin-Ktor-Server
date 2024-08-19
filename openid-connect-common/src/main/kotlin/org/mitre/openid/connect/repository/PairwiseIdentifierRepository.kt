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
package org.mitre.openid.connect.repository

import org.mitre.openid.connect.model.PairwiseIdentifier

/**
 * @author jricher
 */
interface PairwiseIdentifierRepository {
    /**
     * Get a pairwise identifier by its associated user subject and sector identifier.
     *
     */
    fun getBySectorIdentifier(sub: String, sectorIdentifierUri: String): PairwiseIdentifier?

    /**
     * Save a pairwise identifier to the database.
     *
     */
    fun save(pairwise: PairwiseIdentifier): PairwiseIdentifier
}
