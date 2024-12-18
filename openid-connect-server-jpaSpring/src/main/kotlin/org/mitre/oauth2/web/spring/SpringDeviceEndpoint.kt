package org.mitre.oauth2.web.spring

import io.github.pdvrieze.openid.spring.fromSpring
import org.apache.http.client.utils.URIBuilder
import org.mitre.oauth2.exception.DeviceCodeCreationException
import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.DeviceCode
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.DeviceCodeService
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.oauth2.token.DeviceTokenGranter
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.view.HttpCodeView
import org.mitre.util.getLogger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.common.exceptions.InvalidClientException
import org.springframework.security.oauth2.common.util.OAuth2Utils
import org.springframework.security.oauth2.provider.AuthorizationRequest
import org.springframework.security.oauth2.provider.OAuth2RequestFactory
import org.springframework.stereotype.Controller
import org.springframework.ui.ModelMap
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.RequestParam
import java.net.URISyntaxException
import java.time.Duration
import java.time.Instant
import java.util.*
import javax.servlet.http.HttpSession

/**
 * Implements https://tools.ietf.org/html/draft-ietf-oauth-device-flow
 *
 * @see DeviceTokenGranter
 *
 *
 * @author jricher
 */
@Controller
class SpringDeviceEndpoint {
    @Autowired
    private lateinit var clientService: ClientDetailsEntityService

    @Autowired
    private lateinit var scopeService: SystemScopeService

    @Autowired
    private lateinit var config: ConfigurationPropertiesBean

    @Autowired
    private lateinit var deviceCodeService: DeviceCodeService

    @Autowired
    private lateinit var oAuth2RequestFactory: OAuth2RequestFactory

    @RequestMapping(value = ["/$URL"], method = [RequestMethod.POST], consumes = [MediaType.APPLICATION_FORM_URLENCODED_VALUE], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun requestDeviceCode(
        @RequestParam("client_id") clientId: String,
        @RequestParam(name = "scope", required = false) scope: String?,
        parameters: Map<String, String>?,
        model: ModelMap
    ): String {
        val client: OAuthClientDetails?
        try {
            client = clientService.loadClientByClientId(clientId) ?: run {
                logger.error("could not find client $clientId")
                model[HttpCodeView.CODE] = HttpStatus.NOT_FOUND
                return HttpCodeView.VIEWNAME
            }

            // make sure this client can do the device flow
            val authorizedGrantTypes= client.authorizedGrantTypes
            if (!authorizedGrantTypes.isNullOrEmpty()
                && DeviceTokenGranter.GRANT_TYPE !in authorizedGrantTypes
            ) {
                throw InvalidClientException("Unauthorized grant type: " + DeviceTokenGranter.GRANT_TYPE)
            }
        } catch (e: IllegalArgumentException) {
            logger.error("IllegalArgumentException was thrown when attempting to load client", e)
            model[HttpCodeView.CODE] = HttpStatus.BAD_REQUEST
            return HttpCodeView.VIEWNAME
        }

        // make sure the client is allowed to ask for those scopes
        val requestedScopes = OAuth2Utils.parseParameterList(scope)
        val allowedScopes = client.scope

        if (!scopeService.scopesMatch(allowedScopes, requestedScopes)) {
            // client asked for scopes it can't have
            logger.error("Client asked for $requestedScopes but is allowed $allowedScopes")
            model[HttpCodeView.CODE] = HttpStatus.BAD_REQUEST
            model[org.mitre.openid.connect.view.JsonErrorView.ERROR] = "invalid_scope"
            return org.mitre.openid.connect.view.JsonErrorView.VIEWNAME
        }

        // if we got here the request is legit
        try {
            val validity = client.deviceCodeValiditySeconds?.let { Duration.ofSeconds(it) } ?: config.defaultDeviceCodeValiditySeconds
            val expiration = Instant.now()+validity
            val dc = deviceCodeService.createNewDeviceCode(requestedScopes, client, expiration, parameters)

            val response: MutableMap<String, Any?> = HashMap()
            response["device_code"] = dc.deviceCode
            response["user_code"] = dc.userCode
            response["verification_uri"] = config.issuer + USER_URL
            response["expires_in"] = validity

            if (config.isAllowCompleteDeviceCodeUri) {
                val verificationUriComplete = URIBuilder(config.issuer + USER_URL)
                    .addParameter("user_code", dc.userCode)
                    .build()

                response["verification_uri_complete"] = verificationUriComplete.toString()
            }

            model[org.mitre.openid.connect.view.JsonEntityView.ENTITY] = response


            return org.mitre.openid.connect.view.JsonEntityView.VIEWNAME
        } catch (dcce: DeviceCodeCreationException) {
            model[HttpCodeView.CODE] = HttpStatus.BAD_REQUEST
            model[org.mitre.openid.connect.view.JsonErrorView.ERROR] = dcce.error
            model[org.mitre.openid.connect.view.JsonErrorView.ERROR_MESSAGE] = dcce.message

            return org.mitre.openid.connect.view.JsonErrorView.VIEWNAME
        } catch (use: URISyntaxException) {
            logger.error("unable to build verification_uri_complete due to wrong syntax of uri components")
            model[HttpCodeView.CODE] = HttpStatus.INTERNAL_SERVER_ERROR

            return HttpCodeView.VIEWNAME
        }
    }

    @PreAuthorize("hasRole('ROLE_USER')")
    @RequestMapping(value = ["/" + USER_URL], method = [RequestMethod.GET])
    fun requestUserCode(
        @RequestParam(value = "user_code", required = false) userCode: String?,
        model: ModelMap,
        session: HttpSession
    ): String {
        return if (!config.isAllowCompleteDeviceCodeUri || userCode == null) {
            // if we don't allow the complete URI or we didn't get a user code on the way in,
            // print out a page that asks the user to enter their user code
            // user must be logged in
            "requestUserCode"
        } else {
            // complete verification uri was used, we received user code directly
            // skip requesting code page
            // user must be logged in

            readUserCode(userCode, model, session)
        }
    }

    @PreAuthorize("hasRole('ROLE_USER')")
    @RequestMapping(value = ["/" + USER_URL + "/verify"], method = [RequestMethod.POST])
    fun readUserCode(@RequestParam("user_code") userCode: String?, model: ModelMap, session: HttpSession): String {
        // look up the request based on the user code

        val dc = deviceCodeService.lookUpByUserCode(userCode!!)

        // we couldn't find the device code
        if (dc == null) {
            model.addAttribute("error", "noUserCode")
            return "requestUserCode"
        }

        // make sure the code hasn't expired yet
        if (dc.expiration != null && dc.expiration!!.before(Date())) {
            model.addAttribute("error", "expiredUserCode")
            return "requestUserCode"
        }

        // make sure the device code hasn't already been approved
        if (dc.isApproved == true) {
            model.addAttribute("error", "userCodeAlreadyApproved")
            return "requestUserCode"
        }

        val client = clientService.loadClientByClientId(dc.clientId!!)

        model["client"] = client
        model["dc"] = dc

        // pre-process the scopes
        val scopes: Set<SystemScope> = scopeService.fromStrings(dc.scope!!) ?: emptySet()

        val sortedScopes: MutableSet<SystemScope?> = LinkedHashSet(scopes.size)
        val systemScopes: Set<SystemScope?> = scopeService.all

        // sort scopes for display based on the inherent order of system scopes
        for (s in systemScopes) {
            if (scopes.contains(s)) {
                sortedScopes.add(s)
            }
        }

        // add in any scopes that aren't system scopes to the end of the list
        sortedScopes.addAll(scopes - systemScopes)

        model["scopes"] = sortedScopes

        val authorizationRequest = oAuth2RequestFactory.createAuthorizationRequest(dc.requestParameters)

        session.setAttribute("authorizationRequest", authorizationRequest)
        session.setAttribute("deviceCode", dc)

        return "approveDevice"
    }

    @PreAuthorize("hasRole('ROLE_USER')")
    @RequestMapping(value = ["/" + USER_URL + "/approve"], method = [RequestMethod.POST])
    fun approveDevice(
        @RequestParam("user_code") userCode: String,
        @RequestParam(value = "user_oauth_approval") approve: Boolean?,
        model: ModelMap,
        auth: Authentication?,
        session: HttpSession
    ): String {
        val authorizationRequest = session.getAttribute("authorizationRequest") as AuthorizationRequest
        val dc = session.getAttribute("deviceCode") as DeviceCode

        // make sure the form that was submitted is the one that we were expecting
        if (dc.userCode != userCode) {
            model.addAttribute("error", "userCodeMismatch")
            return "requestUserCode"
        }

        // make sure the code hasn't expired yet
        if (dc.expiration != null && dc.expiration!!.before(Date())) {
            model.addAttribute("error", "expiredUserCode")
            return "requestUserCode"
        }

        val client = clientService.loadClientByClientId(dc.clientId!!)

        model["client"] = client

        // user did not approve
        if (!approve!!) {
            model.addAttribute("approved", false)
            return "deviceApproved"
        }

        // create an OAuth request for storage
        val o2req = oAuth2RequestFactory.createOAuth2Request(authorizationRequest).fromSpring()
        val o2Auth = AuthenticatedAuthorizationRequest(o2req, auth?.fromSpring())

        val approvedCode = deviceCodeService.approveDeviceCode(dc, o2Auth)


        // pre-process the scopes
        val scopes: Set<SystemScope> = scopeService.fromStrings(dc.scope!!)?: emptySet()

        val sortedScopes: MutableSet<SystemScope> = LinkedHashSet(scopes.size)
        val systemScopes: Set<SystemScope> = scopeService.all

        // sort scopes for display based on the inherent order of system scopes
        for (s in systemScopes) {
            if (scopes.contains(s)) {
                sortedScopes.add(s)
            }
        }

        // add in any scopes that aren't system scopes to the end of the list
        sortedScopes.addAll(scopes.minus(systemScopes))

        model["scopes"] = sortedScopes
        model["approved"] = true

        return "deviceApproved"
    }

    companion object {
        const val URL: String = "devicecode"
        const val USER_URL: String = "device"

        val logger = getLogger<SpringDeviceEndpoint>()
    }
}
