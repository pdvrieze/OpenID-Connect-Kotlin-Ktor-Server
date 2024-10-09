package org.mitre.openid.connect.service.impl.ktor

import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.openid.connect.repository.UserInfoRepository
import org.mitre.openid.connect.service.PairwiseIdentifierService
import org.mitre.openid.connect.service.impl.AbstractUserInfoService

class DefaultUserInfoService(
    override val userInfoRepository: UserInfoRepository,
    override val clientService: ClientDetailsEntityService,
    override val pairwiseIdentifierService: PairwiseIdentifierService
) : AbstractUserInfoService()
