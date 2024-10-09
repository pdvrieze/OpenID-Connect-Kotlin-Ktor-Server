package org.mitre.openid.connect.service.impl.spring

import org.mitre.openid.connect.repository.BlacklistedSiteRepository
import org.mitre.openid.connect.service.impl.AbstractBlacklistedSiteService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
@Transactional(value = "defaultTransactionManager")
class SpringBlacklistedSiteService: AbstractBlacklistedSiteService {
    @Autowired
    override lateinit var repository: BlacklistedSiteRepository

    constructor() : super()
    constructor(repository: BlacklistedSiteRepository) : super() {
        this.repository = repository
    }
}
