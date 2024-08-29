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
package org.mitre.openid.connect.service.impl

import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.openid.connect.model.PairwiseIdentifier
import org.mitre.openid.connect.model.UserInfo
import org.mitre.openid.connect.repository.PairwiseIdentifierRepository
import org.mitre.openid.connect.service.PairwiseIdentiferService
import org.mitre.util.getLogger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service
import org.springframework.web.util.UriComponentsBuilder
import java.util.*

/**
 * @author jricher
 */
@Service("uuidPairwiseIdentiferService")
class UUIDPairwiseIdentiferService : PairwiseIdentiferService {
    @Autowired
    private lateinit var pairwiseIdentifierRepository: PairwiseIdentifierRepository

    override fun getIdentifier(userInfo: UserInfo, client: OAuthClientDetails): String? {
        val sectorIdentifier: String?

        val sectorIdentifierUri = client.sectorIdentifierUri
        if (!sectorIdentifierUri.isNullOrEmpty()) {
            val uri = UriComponentsBuilder.fromUriString(sectorIdentifierUri).build()
            sectorIdentifier = uri.host // calculate based on the host component only
        } else {
            val redirectUris = client.redirectUris
            val uri = UriComponentsBuilder.fromUriString(redirectUris.single()).build()
            sectorIdentifier = uri.host // calculate based on the host of the only redirect URI
        }

        if (sectorIdentifier != null) {
            // if there's a sector identifier, use that for the lookup
            var pairwise = pairwiseIdentifierRepository.getBySectorIdentifier(userInfo.sub!!, sectorIdentifier)

            if (pairwise == null) {
                // we don't have an identifier, need to make and save one

                pairwise = PairwiseIdentifier()
                pairwise.identifier = UUID.randomUUID().toString()
                pairwise.userSub = userInfo.sub
                pairwise.sectorIdentifier = sectorIdentifier

                pairwiseIdentifierRepository.save(pairwise)
            }

            return pairwise.identifier
        } else {
            return null
        }
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<UUIDPairwiseIdentiferService>()
    }
}
