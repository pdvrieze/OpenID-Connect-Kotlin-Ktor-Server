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
package org.mitre.openid.connect.model

/**
 *
 * Holds the generated pairwise identifiers for a user. Can be tied to either a client ID or a sector identifier URL.
 *
 * @author jricher
 */
//@NamedQueries(NamedQuery(name = PairwiseIdentifier.QUERY_ALL, query = "select p from PairwiseIdentifier p"), NamedQuery(name = PairwiseIdentifier.QUERY_BY_SECTOR_IDENTIFIER, query = "select p from PairwiseIdentifier p WHERE p.userSub = :" + PairwiseIdentifier.PARAM_SUB + " AND p.sectorIdentifier = :" + PairwiseIdentifier.PARAM_SECTOR_IDENTIFIER))
class PairwiseIdentifier(
    var id: Long? = null,
    var identifier: String? = null,
    userSubject: String,
    sectorIdentifier: String
) {
    var userSub: String? = userSubject
    var sectorIdentifier: String? = sectorIdentifier

    fun copy(
        id: Long? = this.id,
        identifier: String? = this.identifier,
        userSubject: String = this.userSub!!,
        sectorIdentifier: String = this.sectorIdentifier!!
    ) : PairwiseIdentifier {
        return PairwiseIdentifier(id, identifier, userSubject, sectorIdentifier)
    }

    companion object {
        const val QUERY_BY_SECTOR_IDENTIFIER: String = "PairwiseIdentifier.getBySectorIdentifier"
        const val QUERY_ALL: String = "PairwiseIdentifier.getAll"

        const val PARAM_SECTOR_IDENTIFIER: String = "sectorIdentifier"
        const val PARAM_SUB: String = "sub"
    }
}
