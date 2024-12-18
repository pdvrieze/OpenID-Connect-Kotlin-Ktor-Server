package io.github.pdvrieze.openid.spring

import io.github.pdvrieze.auth.Authentication
import io.github.pdvrieze.auth.ClientAuthentication
import io.github.pdvrieze.auth.SavedAuthentication
import io.github.pdvrieze.auth.TokenAuthentication
import io.github.pdvrieze.auth.UserAuthentication
import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.LocalGrantedAuthority
import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuth2RefreshToken
import org.mitre.oauth2.model.OldSavedUserAuthentication
import org.mitre.oauth2.model.request.AuthorizationRequest
import org.mitre.oauth2.model.request.InternalForStorage
import org.mitre.oauth2.model.request.OpenIdAuthorizationRequest
import org.mitre.oauth2.model.request.PlainAuthorizationRequest
import org.mitre.openid.connect.model.OIDCAuthenticationToken
import org.mitre.openid.connect.model.PendingOIDCAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import java.time.Instant
import java.util.*
import org.springframework.security.core.Authentication as SpringAuthentication
import org.springframework.security.core.GrantedAuthority as SpringGrantedAuthority
import org.springframework.security.oauth2.common.OAuth2AccessToken as SpringOAuth2AccessToken
import org.springframework.security.oauth2.common.OAuth2RefreshToken as SpringOAuth2RefreshToken
import org.springframework.security.oauth2.provider.OAuth2Authentication as SpringOAuth2Authentication
import org.springframework.security.oauth2.provider.OAuth2Request as SpringOAuth2Request

interface SpringFacade<T : Any> {
    val original: T
}

fun OAuth2AccessToken.toSpring(): SpringOAuth2AccessToken {
    return object : SpringOAuth2AccessToken, SpringFacade<OAuth2AccessToken> {
        override val original = this@toSpring

        override fun getAdditionalInformation(): Map<String, Any> = emptyMap()

        override fun getScope(): Set<String> = original.scope

        override fun getRefreshToken(): SpringOAuth2RefreshToken? {
            return original.refreshToken?.toSpring()
        }

        override fun getTokenType(): String = original.tokenType

        override fun isExpired(): Boolean = original.isExpired

        @Suppress("DEPRECATION")
        override fun getExpiration(): Date? = original.expiration

        override fun getExpiresIn(): Int = original.expiresIn

        override fun getValue(): String = original.value
    }
}

fun OAuth2RefreshToken.toSpring(): SpringOAuth2RefreshToken {
    return object: SpringOAuth2RefreshToken, SpringFacade<OAuth2RefreshToken> {
        override val original = this@toSpring

        override fun getValue(): String = original.value
    }

}

fun OldSavedUserAuthentication.toSpring(): SpringAuthentication {
    return object: SpringAuthentication, SpringFacade<OldSavedUserAuthentication> {
        override val original: OldSavedUserAuthentication = this@toSpring
        override fun getName(): String = original.name

        override fun getAuthorities(): Collection<SpringGrantedAuthority> {
            return original.authorities.map { SimpleGrantedAuthority(it.authority) }.toMutableList()
        }

        override fun getCredentials(): Any? = null

        override fun getDetails(): Any? = null

        override fun getPrincipal(): Any {
            return original.name
        }

        override fun isAuthenticated(): Boolean = original.isAuthenticated

        override fun setAuthenticated(isAuthenticated: Boolean) {
            throw UnsupportedOperationException("Setting authentication is not available on the wrapped type")
        }
    }
}

fun Authentication.toSpring(): SpringAuthentication {
    return object: SpringAuthentication, SpringFacade<Authentication> {
        override val original: Authentication = this@toSpring
        override fun getName(): String = when (val o = original) {
            is UserAuthentication -> o.userId
            is ClientAuthentication -> o.clientId
            is SavedAuthentication -> o.principalName
            is TokenAuthentication -> o.principalName
        }

        override fun getAuthorities(): Collection<SpringGrantedAuthority> {
            return original.authorities.orEmpty().map { SimpleGrantedAuthority(it.authority) }.toMutableList()
        }

        override fun getCredentials(): Any? = null

        override fun getDetails(): Any? = null

        override fun getPrincipal(): Any {
            return name
        }

        override fun isAuthenticated(): Boolean = original.authTime.isAfter(Instant.EPOCH)

        override fun setAuthenticated(isAuthenticated: Boolean) {
            throw UnsupportedOperationException("Setting authentication is not available on the wrapped type")
        }
    }
}

fun AuthenticatedAuthorizationRequest.toSpring(): SpringOAuth2Authentication =
    SpringOAuth2Authentication(authorizationRequest.toSpring(), subjectAuth?.toSpring())

@OptIn(InternalForStorage::class)
fun AuthorizationRequest.toSpring(): SpringOAuth2Request =
    SpringOAuth2Request(
        requestParameters,
        clientId,
        authorities.map { SimpleGrantedAuthority(it.authority) },
        isApproved,
        scope,
        resourceIds,
        redirectUri,
        responseTypes,
        authHolderExtensions
    )

fun PendingOIDCAuthenticationToken.toSpring(): SpringAuthentication {
    return object : SpringAuthentication, SpringFacade<PendingOIDCAuthenticationToken> {
        override val original = this@toSpring

        override fun getName(): String = original.name

        override fun getAuthorities(): Collection<SpringGrantedAuthority> {
            return original.authorities.map { SimpleGrantedAuthority(it.authority) }
        }

        override fun getCredentials(): Any {
            return original.getCredentials()
        }

        override fun getDetails(): Any {
            TODO()
        }

        override fun getPrincipal(): Any {
            return original.getPrincipal()
        }

        override fun isAuthenticated(): Boolean {
            return original.isAuthenticated
        }

        override fun setAuthenticated(isAuthenticated: Boolean) {
            throw UnsupportedOperationException("Setting authentication is not available on the wrapped type")
        }
    }
}

fun OIDCAuthenticationToken.toSpring(): SpringAuthentication {
    return object: SpringAuthentication, SpringFacade<OIDCAuthenticationToken> {
        override val original: OIDCAuthenticationToken get() = this@toSpring

        override fun getName(): String = original.name

        override fun getAuthorities(): Collection<SpringGrantedAuthority> {
            return original.authorities.map { SimpleGrantedAuthority(it.authority) }
        }

        override fun getCredentials(): Any = original.getCredentials()

        override fun getDetails(): Any? {
            return null
        }

        override fun getPrincipal(): Any {
            return original.getPrincipal()
        }

        override fun isAuthenticated(): Boolean {
            return original.isAuthenticated
        }

        override fun setAuthenticated(isAuthenticated: Boolean) {
            throw UnsupportedOperationException("Setting authentication is not available on the wrapped type")
        }
    }
}

fun SpringOAuth2Authentication.fromSpring(): AuthenticatedAuthorizationRequest {
    return AuthenticatedAuthorizationRequest(
        authorizationRequest = oAuth2Request.fromSpring(),
        userAuthentication = userAuthentication?.fromSpring(),
    )
}

fun SpringAuthentication.fromSpring(): SavedAuthentication {
    return SavedAuthentication(
        principalName = name,
        id = null,
        authTime = if (isAuthenticated) Instant.ofEpochSecond(1L) else Instant.EPOCH,
        authorities = authorities.map { LocalGrantedAuthority(it.authority) },
        scope = emptySet(),
        sourceClass = this.javaClass.name // no known scopes
    )
}

@OptIn(InternalForStorage::class)
fun SpringOAuth2Request.fromSpring(): AuthorizationRequest = when {
    "openid" in scope -> OpenIdAuthorizationRequest.Builder(clientId).also { b ->
        extensions?.mapValues { it.toString() }?.let { b.setFromExtensions(it) }
        b.requestParameters = requestParameters
        b.clientId = clientId
        b.authorities = authorities.mapTo(HashSet()) { LocalGrantedAuthority(it.authority) }
        if (isApproved && b.approval == null) {
            b.approval = AuthorizationRequest.Approval(Instant.EPOCH) // mark long ago //setFromExtensions should handle this
        }
        b.scope = scope
        b.resourceIds = resourceIds
        b.redirectUri = redirectUri
        b.responseTypes = responseTypes
        b.state = requestParameters["state"]
        b.requestTime = Instant.EPOCH
    }.build()

    else -> PlainAuthorizationRequest.Builder(clientId).also { b ->
        b.setFromExtensions(extensions?.mapValues { it.toString() } ?: emptyMap())
        b.requestParameters = requestParameters
        b.clientId = clientId
        b.authorities = authorities.mapTo(HashSet()) { LocalGrantedAuthority(it.authority) }
        if (isApproved && b.approval == null) {
            b.approval = AuthorizationRequest.Approval(Instant.EPOCH) // mark long ago //setFromExtensions should handle this
        }

        b.scope = scope
        b.resourceIds = resourceIds
        b.redirectUri = redirectUri
        b.responseTypes = responseTypes
        b.requestTime = Instant.EPOCH
    }.build()
}
