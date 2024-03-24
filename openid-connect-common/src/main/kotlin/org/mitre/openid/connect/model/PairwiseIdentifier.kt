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

import javax.persistence.Basic
import javax.persistence.Column
import javax.persistence.Entity
import javax.persistence.GeneratedValue
import javax.persistence.GenerationType
import javax.persistence.Id
import javax.persistence.NamedQueries
import javax.persistence.NamedQuery
import javax.persistence.Table

/**
 *
 * Holds the generated pairwise identifiers for a user. Can be tied to either a client ID or a sector identifier URL.
 *
 * @author jricher
 */
@Entity
@Table(name = "pairwise_identifier")
@NamedQueries(NamedQuery(name = PairwiseIdentifier.QUERY_ALL, query = "select p from PairwiseIdentifier p"), NamedQuery(name = PairwiseIdentifier.QUERY_BY_SECTOR_IDENTIFIER, query = "select p from PairwiseIdentifier p WHERE p.userSub = :" + PairwiseIdentifier.PARAM_SUB + " AND p.sectorIdentifier = :" + PairwiseIdentifier.PARAM_SECTOR_IDENTIFIER))
class PairwiseIdentifier {
    @get:Column(name = "id")
    @get:GeneratedValue(strategy = GenerationType.IDENTITY)
    @get:Id
    var id: Long? = null

    @get:Column(name = "identifier")
    @get:Basic
    var identifier: String? = null

    @get:Column(name = PARAM_SUB)
    @get:Basic
    var userSub: String? = null

    @get:Column(name = "sector_identifier")
    @get:Basic
    var sectorIdentifier: String? = null

    companion object {
        const val QUERY_BY_SECTOR_IDENTIFIER: String = "PairwiseIdentifier.getBySectorIdentifier"
        const val QUERY_ALL: String = "PairwiseIdentifier.getAll"

        const val PARAM_SECTOR_IDENTIFIER: String = "sectorIdentifier"
        const val PARAM_SUB: String = "sub"
    }
}
