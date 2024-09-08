package io.github.pdvrieze.auth.service.impl

import org.mitre.oauth2.exception.AuthenticationException
import org.mitre.oauth2.exception.InvalidGrantException
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.service.RedirectResolver
import java.net.MalformedURLException
import java.net.URL

abstract class AbstractRedirectResolver(
    redirectGrantTypes: Collection<String> = listOf("implicit", "authorization_code"),
    val matchPorts: Boolean = true
) : RedirectResolver {

    val redirectGrantTypes: List<String> = redirectGrantTypes.toList()

    override fun resolveRedirect(requestedRedirect: String, client: OAuthClientDetails): String {
        val authorizedGrantTypes = client.getAuthorizedGrantTypes()
        if (authorizedGrantTypes.isEmpty()) {
            throw InvalidGrantException("A client must have at least one authorized grant type.")
        }
        if ( authorizedGrantTypes.none { it in redirectGrantTypes }) {
            throw InvalidGrantException("A redirect_uri can only be used by implicit or authorization_code grant types.")
        }

        val redirectUris = client.getRegisteredRedirectUri()

        return if (!redirectUris.isNullOrEmpty()) {
            obtainMatchingRedirect(redirectUris, requestedRedirect)
        } else if (requestedRedirect.isNotBlank()) {
            requestedRedirect
        } else {
            throw AuthenticationException("A redirect_uri must be supplied.")
        }
    }


    private fun obtainMatchingRedirect(redirectUris: Set<String>, requestedRedirect: String?): String {
        require(redirectUris.isNotEmpty()) { "At least one redirect uri is required" }

        if (requestedRedirect == null) {
            if (redirectUris.size == 1) return redirectUris.first()
        } else {
            redirectUris.firstOrNull { redirectMatches(requestedRedirect, it) }
                ?.let { return it }
        }

        throw RedirectResolver.RedirectMismatchException(
            "Invalid redirect: $requestedRedirect does not match one of the registered values: $redirectUris"
        )
    }

    override fun redirectMatches(requestedRedirect: String, redirectUri: String): Boolean {
        try {
            val req = URL(requestedRedirect)
            val reg = URL(redirectUri)

            val requestedPort = if (req.port != -1) req.port else req.defaultPort
            val registeredPort = if (reg.port != -1) reg.port else reg.defaultPort

            val portsMatch = if (matchPorts) (registeredPort == requestedPort) else true

            if (reg.protocol == req.protocol &&
                reg.host ==  req.host && // TODO doesn't allow subdomains
                portsMatch
            ) {
                return req.path.startsWith(reg.path) // unlike mitre, be stricter on path match (no normalisation)
            }
        } catch (e: MalformedURLException) {
        }
        return requestedRedirect == redirectUri
    }
}
