package org.mitre.openid.connect.view

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.util.pipeline.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.jwt.signer.service.impl.ClientKeyCacheService
import org.mitre.jwt.signer.service.impl.SymmetricKeyJWTValidatorCacheService
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.model.UserInfo
import org.mitre.openid.connect.service.ScopeClaimTranslationService
import org.mitre.util.getLogger

suspend fun PipelineContext<Unit, ApplicationCall>.userInfoView(
    jwtService: JWTSigningAndValidationService,
    config: ConfigurationPropertiesBean,
    encrypters: ClientKeyCacheService,
    symmetricCacheService: SymmetricKeyJWTValidatorCacheService,
    translator: ScopeClaimTranslationService,
    userInfo: UserInfo,
    scope: Set<String>,
    client: OAuthClientDetails,
    authorizedClaims: String? = null,
    requestedClaims: String? = null,
    code: HttpStatusCode = HttpStatusCode.OK,
) {
    val authorizedClaims: JsonObject? = authorizedClaims?.let { Json.parseToJsonElement(it) as? JsonObject }
    val requestedClaims: JsonObject? = requestedClaims?.let { Json.parseToJsonElement(it) as? JsonObject }

    val json = UserInfoView.toJsonFromRequestObj(userInfo, scope, authorizedClaims, requestedClaims, translator)
    userInfoJWTView(encrypters, symmetricCacheService, json, client, code)
}

object UserInfoView {
    /**
     * Build a JSON response according to the request object received.
     *
     * Claims requested in requestObj.userinfo.claims are added to any
     * claims corresponding to requested scopes, if any.
     *
     * @param ui the UserInfo to filter
     * @param scope the allowed scopes to filter by
     * @param authorizedClaims the claims authorized by the client or user
     * @param requestedClaims the claims requested in the RequestObject
     * @return the filtered JsonObject result
     */
    internal fun toJsonFromRequestObj(
        ui: UserInfo?,
        scope: Set<String>,
        authorizedClaims: JsonObject?,
        requestedClaims: JsonObject?,
        translator: ScopeClaimTranslationService,
    ): JsonObject {
        // get the base object

        val obj = ui!!.toJson()

        val allowedByScope = translator.getClaimsForScopeSet(scope)
        val authorizedByClaims = extractUserInfoClaimsIntoSet(authorizedClaims)
        val requestedByClaims = extractUserInfoClaimsIntoSet(requestedClaims)

        // Filter claims by performing a manual intersection of claims that are allowed by the given scope, requested, and authorized.
        // We cannot use Sets.intersection() or similar because Entry<> objects will evaluate to being unequal if their values are
        // different, whereas we are only interested in matching the Entry<>'s key values.
        val result = mutableMapOf<String, JsonElement>()
        for ((key, value) in obj.entries) {
            if (allowedByScope!!.contains(key)
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
    private fun extractUserInfoClaimsIntoSet(claims: JsonObject?): Set<String> {
        val target: MutableSet<String> = HashSet()
        if (claims != null) {
            val userinfoAuthorized = claims["userinfo"] as? JsonObject
            if (userinfoAuthorized != null) {
                for (key in userinfoAuthorized.keys) {
                    target.add(key)
                }
            }
        }
        return target
    }

    const val REQUESTED_CLAIMS: String = "requestedClaims"
    const val AUTHORIZED_CLAIMS: String = "authorizedClaims"
    const val SCOPE: String = "scope"
    const val USER_INFO: String = "userInfo"

    const val VIEWNAME: String = "userInfoView"
    private val logger = getLogger<UserInfoView>()
}
