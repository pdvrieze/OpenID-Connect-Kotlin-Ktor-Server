package org.mitre.openid.connect.view

import io.ktor.http.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import org.mitre.jwt.signer.service.ClientKeyCacheService
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.jwt.signer.service.impl.SymmetricKeyJWTValidatorCacheService
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.request.OpenIdAuthorizationRequest.ClaimsRequest
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.model.UserInfo
import org.mitre.openid.connect.service.ScopeClaimTranslationService
import org.mitre.util.getLogger
import org.mitre.util.oidJson

/**
 * @param authorizedByClaims the claims authorized by the client or user
 * @param requestedByClaims the claims requested in the RequestObject
 */
suspend fun RoutingContext.userInfoView(
    jwtService: JWTSigningAndValidationService,
    config: ConfigurationPropertiesBean,
    encrypters: ClientKeyCacheService,
    symmetricCacheService: SymmetricKeyJWTValidatorCacheService,
    translator: ScopeClaimTranslationService,
    userInfo: UserInfo,
    scope: Set<String>,
    client: OAuthClientDetails,
    authorizedByClaims: ClaimsRequest? = null,
    requestedByClaims: ClaimsRequest? = null,
    code: HttpStatusCode = HttpStatusCode.OK,
) {

    val json = UserInfoView.toJsonFromRequestObj(userInfo, scope, authorizedByClaims, requestedByClaims, translator)
    userInfoJWTView(encrypters, symmetricCacheService, json, client, code)
}

object UserInfoView {
    /**
     * Build a JSON response according to the request object received.
     *
     * Claims requested in requestObj.userinfo.claims are added to any claims
     * corresponding to requested scopes, if any.
     *
     * @param ui the UserInfo to filter
     * @param scope the allowed scopes to filter by
     * @param authorizedByClaims the claims authorized by the client or user
     * @param requestedByClaims the claims requested in the RequestObject
     * @return the filtered JsonObject result
     */
    internal fun toJsonFromRequestObj(
        ui: UserInfo?,
        scope: Set<String>,
        authorizedByClaims: ClaimsRequest?,
        requestedByClaims: ClaimsRequest?,
        translator: ScopeClaimTranslationService,
    ): JsonObject {
        // get the base object

        val obj = ui!!.toJson()

        val allowedByScope = translator.getClaimsForScopeSet(scope)
        val authorizedByClaims = extractUserInfoClaimsIntoSet(authorizedByClaims)
        val requestedByClaims = extractUserInfoClaimsIntoSet(requestedByClaims)

        // Filter claims by performing a manual intersection of claims that are allowed by the given scope, requested, and authorized.
        // We cannot use Sets.intersection() or similar because Entry<> objects will evaluate to being unequal if their values are
        // different, whereas we are only interested in matching the Entry<>'s key values.
        val result = mutableMapOf<String, JsonElement>()
        for ((key, value) in obj.entries) {
            if (allowedByScope.contains(key)
                || authorizedByClaims.contains(key)
            ) {
                // it's allowed either by scope or by the authorized claims (either way is fine with us)

                if (requestedByClaims.isEmpty() || requestedByClaims.contains(key)) {
                    // the requested claims are empty (so we allow all), or they're not empty and this claim was specifically asked for
                    result.put(key, value)
                } // otherwise there were specific claims requested and this wasn't one of them
            }
        }

        return JsonObject(result)
    }

    /**
     * Pull the claims that have been targeted into a set for processing.
     * Returns an empty set if the input is null.
     * @param claims the claims request to process
     */
    private fun extractUserInfoClaimsIntoSet(claims: ClaimsRequest?): Set<String> {
        val userinfoAuthorized = claims?.userInfo ?: return emptySet()
        return buildSet {
            addAll(userinfoAuthorized.claimRequests.keys.asSequence().map { it.name })
        }
    }

    const val REQUESTED_CLAIMS: String = "requestedClaims"
    const val AUTHORIZED_CLAIMS: String = "authorizedClaims"
    const val SCOPE: String = "scope"
    const val USER_INFO: String = "userInfo"

    const val VIEWNAME: String = "userInfoView"
    private val logger = getLogger<UserInfoView>()
}
