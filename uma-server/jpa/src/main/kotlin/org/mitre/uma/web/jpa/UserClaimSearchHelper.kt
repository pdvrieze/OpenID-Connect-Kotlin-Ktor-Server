package org.mitre.uma.web.jpa

import kotlinx.coroutines.runBlocking
import org.mitre.openid.connect.client.service.impl.WebfingerIssuerService
import org.mitre.openid.connect.client.service.jpa.getIssuer
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.service.UserInfoService
import org.mitre.openid.connect.view.HttpCodeView
import org.mitre.openid.connect.view.JsonEntityView
import org.mitre.openid.connect.view.JsonErrorView
import org.mitre.openid.connect.web.RootController
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.util.MimeTypeUtils
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.RequestParam
import javax.servlet.http.HttpServletRequest

/**
 * @author jricher
 */
@Controller
@RequestMapping("/" + UserClaimSearchHelper.URL)
@PreAuthorize("hasRole('ROLE_USER')")
class UserClaimSearchHelper {
    private val webfingerIssuerService = WebfingerIssuerService()

    @Autowired
    private lateinit var userInfoService: UserInfoService

    @Autowired
    private lateinit var config: ConfigurationPropertiesBean


    @RequestMapping(method = [RequestMethod.GET], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    fun search(
        @RequestParam(value = "identifier") email: String,
        m: Model,
        auth: Authentication?,
        req: HttpServletRequest?
    ): String {
        // check locally first

        val localUser = userInfoService.getByEmailAddress(email)

        if (localUser != null) {
            val e = mapOf(
                "issuer" to setOf(config.issuer),
                "name" to "email",
                "value" to localUser.email,
            )

            val ev = mapOf(
                "issuer" to setOf(config.issuer),
                "name" to "email_verified",
                "value" to localUser.emailVerified,
            )

            val s = mapOf(
                "issuer" to setOf(config.issuer),
                "name" to "sub",
                "value" to localUser.subject,
            )

            m.addAttribute(JsonEntityView.ENTITY, setOf(e, ev, s))
            return JsonEntityView.VIEWNAME
        } else {
            // otherwise do a webfinger lookup

            val resp = runBlocking { webfingerIssuerService.getIssuer(req!!) }

            if (resp?.issuer != null) {
                // we found an issuer, return that
                val e = mapOf(
                    "issuer" to setOf(resp.issuer),
                    "name" to "email",
                    "value" to email,
                )

                val ev = mapOf(
                    "issuer" to setOf(resp.issuer),
                    "name" to "email_verified",
                    "value" to true,
                )

                m.addAttribute(JsonEntityView.ENTITY, setOf(e, ev))
                return JsonEntityView.VIEWNAME
            } else {
                m.addAttribute(HttpCodeView.CODE, HttpStatus.NOT_FOUND)
                return JsonErrorView.VIEWNAME
            }
        }
    }

    companion object {
        const val URL: String = RootController.API_URL + "/emailsearch"
    }
}
