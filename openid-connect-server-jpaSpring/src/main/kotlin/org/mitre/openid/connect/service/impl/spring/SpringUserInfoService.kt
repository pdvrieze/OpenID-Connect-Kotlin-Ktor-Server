package org.mitre.openid.connect.service.impl.spring

import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.openid.connect.repository.UserInfoRepository
import org.mitre.openid.connect.service.PairwiseIdentifierService
import org.mitre.openid.connect.service.impl.AbstractUserInfoService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service

@Service
class SpringUserInfoService : AbstractUserInfoService {
    @Autowired
    override lateinit var userInfoRepository: UserInfoRepository

    @Autowired
    override lateinit var clientService: ClientDetailsEntityService

    @Autowired
    override lateinit var pairwiseIdentifierService: PairwiseIdentifierService

    @Deprecated("Use constructor that doesn't rely on autowiring")
    constructor()

    constructor(
        userInfoRepository: UserInfoRepository,
        clientService: ClientDetailsEntityService,
        pairwiseIdentifierService: PairwiseIdentifierService,
    ) {
        this.userInfoRepository = userInfoRepository
        this.clientService = clientService
        this.pairwiseIdentifierService = pairwiseIdentifierService
    }


}
