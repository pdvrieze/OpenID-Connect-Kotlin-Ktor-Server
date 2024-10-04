package org.mitre.openid.connect.assertion

import com.nimbusds.jwt.JWT
import org.mitre.oauth2.model.Authentication
import org.mitre.oauth2.model.GrantedAuthority

/**
 * @author jricher
 */
class JWTBearerAssertionAuthenticationToken(
    jwt: JWT,
    override val authorities: Collection<GrantedAuthority> = emptySet()
) : Authentication {
    private var _jwt: JWT? = jwt

    val jwt: JWT? get() = _jwt!!

    private var subject: String? = jwt.jwtClaimsSet?.subject

    override val name: String
        get() = subject!!

    override val isAuthenticated: Boolean = authorities.isNotEmpty()

    //    /**
//     * Create an authenticated token with the given clientID, jwt, and authorities set
//     */
//    constructor(jwt: JWT, dummy: Boolean,  authorities: Collection<GrantedAuthority>) : this(jwt, authorities) {
//        try {
//            // save the subject of the JWT in case the credentials get erased later
//            this.subject = jwt.jwtClaimsSet.subject
//        } catch (e: ParseException) {
//            // TODO Auto-generated catch block
//            e.printStackTrace()
//        }
//        this.jwt = jwt
//        isAuthenticated = true
//    }


    /* (non-Javadoc)
	 * @see org.springframework.security.core.Authentication#getCredentials()
	 */
    val credentials: JWT? get() = jwt


    /* (non-Javadoc)
	 * @see org.springframework.security.core.Authentication#getPrincipal()
	 */
    val principal: Any get() = subject!!
    /**
     * Clear out the JWT that this token holds.
     */
    fun eraseCredentials() {
        _jwt = null
    }


    companion object {
        private const val serialVersionUID = -3138213539914074617L
    }
}
