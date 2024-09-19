package io.github.pdvrieze.openid.web

import org.mitre.oauth2.model.Authentication
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.config.UIConfiguration
import org.mitre.openid.connect.model.UserInfo

interface WebContext {
    val userInfo: UserInfo?
    val authentication: Authentication
    val userAuthorities: String?
    val userInfoJson: String? get() = userInfo?.toJson()?.toString()
    val lang: String
    val intl: Intl
    val config: ConfigurationPropertiesBean
    val ui: UIConfiguration
}
