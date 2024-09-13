package org.mitre.openid.connect.service.impl

import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.openid.connect.model.PairwiseIdentifier
import org.mitre.openid.connect.model.UserInfo
import org.mitre.openid.connect.repository.PairwiseIdentifierRepository
import org.mitre.openid.connect.service.PairwiseIdentifierService
import org.mitre.util.getLogger
import org.springframework.web.util.UriComponentsBuilder
import java.util.*

/**
 * @author jricher
 */
abstract class AbstractUUIDPairwiseIdentiferService : PairwiseIdentifierService {
    abstract val pairwiseIdentifierRepository: PairwiseIdentifierRepository

    final override fun getIdentifier(userInfo: UserInfo, client: OAuthClientDetails): String? {
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
            var pairwise = pairwiseIdentifierRepository.getBySectorIdentifier(userInfo.subject, sectorIdentifier)

            if (pairwise == null) {
                // we don't have an identifier, need to make and save one

                pairwise = PairwiseIdentifier(
                    identifier = UUID.randomUUID().toString(),
                    userSubject = userInfo.subject,
                    sectorIdentifier = sectorIdentifier,

                    )

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
        private val logger = getLogger<AbstractUUIDPairwiseIdentiferService>()
    }
}
