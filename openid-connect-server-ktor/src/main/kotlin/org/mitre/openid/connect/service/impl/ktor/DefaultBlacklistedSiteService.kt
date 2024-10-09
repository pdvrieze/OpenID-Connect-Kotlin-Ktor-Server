package org.mitre.openid.connect.service.impl.ktor

import org.mitre.openid.connect.repository.BlacklistedSiteRepository
import org.mitre.openid.connect.service.impl.AbstractBlacklistedSiteService

class DefaultBlacklistedSiteService(override val repository: BlacklistedSiteRepository) :
    AbstractBlacklistedSiteService() {
}
