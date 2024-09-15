package org.mitre.openid.connect.web

import org.mitre.openid.connect.service.UserInfoService

/**
 * Injects the UserInfo object for the current user into the current model's context, if both exist. Allows JSPs and the like to call "userInfo.name" and other fields.
 *
 * @author jricher
 */
class UserInfoInterceptor /*: AsyncHandlerInterceptor*/ {
//    @Autowired(required = false)
    private val userInfoService: UserInfoService? = null

//    private val trustResolver: AuthenticationTrustResolver = AuthenticationTrustResolverImpl()

    @Throws(Exception::class)
    fun preHandle(request: javax.servlet.http.HttpServletRequest, response: javax.servlet.http.HttpServletResponse, handler: Any): Boolean {
        TODO()
/*
        val auth = SecurityContextHolder.getContext().authentication

        if (auth is Authentication) {
            val a = MITREidDataService.json.encodeToString(ListSerializer(SimpleGrantedAuthorityStringConverter()).nullable, auth.authorities?.map { SimpleGrantedAuthority(it.authority) })
            request.setAttribute("userAuthorities", a)
        }

        if (!trustResolver.isAnonymous(auth)) { // skip lookup on anonymous logins
            if (auth is OIDCAuthenticationToken) {
                // if they're logging into this server from a remote OIDC server, pass through their user info
                val oidc = auth
                if (oidc.userInfo != null) {
                    request.setAttribute("userInfo", oidc.userInfo)
                    request.setAttribute("userInfoJson", oidc.userInfo.toJson())
                } else {
                    request.setAttribute("userInfo", null)
                    request.setAttribute("userInfoJson", "null")
                }
            } else {
                // don't bother checking if we don't have a principal or a userInfoService to work with
                if (auth != null && auth.name != null) {
                    // try to look up a user based on the principal's name

                    val user = userInfoService?.getByUsername(auth.name)

                    // if we have one, inject it so views can use it
                    if (user != null) {
                        request.setAttribute("userInfo", user)
                        request.setAttribute("userInfoJson", user.toJson())
                    }
                }
            }
        }

        return true
*/
    }
}
