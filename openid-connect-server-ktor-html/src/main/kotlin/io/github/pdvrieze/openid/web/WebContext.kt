package io.github.pdvrieze.openid.web

import io.github.pdvrieze.auth.Authentication
import io.github.pdvrieze.auth.UserAuthentication
import org.mitre.oauth2.model.OldAuthentication
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.config.UIConfiguration
import org.mitre.openid.connect.model.UserInfo

interface WebContext {
    fun issuerUrl(subPath: String): String = config.issuerUrl(subPath)

    val csrf: ICsrf
    val userInfo: UserInfo?
    val authentication: UserAuthentication?
    val userAuthorities: String?
    val userInfoJson: String? get() = userInfo?.toJson()?.toString()
    val lang: String
    val intl: Intl
    val config: ConfigurationPropertiesBean
    val ui: UIConfiguration

    interface ICsrf {
        fun requireSession()

        val parameterName: String
        val token: String
    }
}
