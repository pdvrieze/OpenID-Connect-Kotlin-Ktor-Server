package org.mitre.oauth2.model.request

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.encoding.encodeStructure
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import org.mitre.oauth2.model.Claim
import org.mitre.oauth2.model.request.OpenIdAuthorizationRequest.ClaimRequest
import org.mitre.openid.connect.model.DefaultAddress
import org.mitre.openid.connect.request.Prompt
import org.mitre.util.asBoolean
import org.mitre.util.asString
import org.mitre.util.oidJson
import java.time.Instant

interface OpenIdAuthorizationRequest : AuthorizationRequest {

    val codeChallenge: CodeChallenge?
    val audience: String?
    val maxAge: Long?
    val approvedSiteId: Long?
    val loginHint: String?
    val prompts: Set<Prompt>?
    val idToken: String? //idtoken
    val nonce: String?
    val requestedClaims: ClaimsRequest?
    val display: String?
    val responseMode: ResponseMode

    override fun builder(): Builder


    class Builder : AuthorizationRequest.Builder {
        constructor(clientId: String) : super(clientId)

        var codeChallenge: CodeChallenge? = null
        var audience: String? = null
        var maxAge: Long? = null
        var approvedSiteId: Long? = null
        var loginHint: String? = null
        var prompts: Set<Prompt>? = null
        var idToken: String? = null //idtoken
        var nonce: String? = null
        var requestedClaims: ClaimsRequest? = null
        var display: String? = null
        var responseMode: ResponseMode = ResponseMode.DEFAULT
        var extensions: Map<String, String>? = null
            private set

        constructor(orig: AuthorizationRequest) : super(orig) {
            if (orig is OpenIdAuthorizationRequest) {
                codeChallenge = orig.codeChallenge
                audience = orig.audience
                maxAge = orig.maxAge
                approvedSiteId = orig.approvedSiteId
                loginHint = orig.loginHint
                prompts = orig.prompts
                idToken = orig.idToken
                nonce = orig.nonce
                display = orig.display
                requestedClaims = orig.requestedClaims
                responseMode = orig.responseMode
            }
        }

        override fun build(): OpenIdAuthorizationRequest {
            return OpenIdAuthorizationRequestImpl(this)
        }

        @InternalForStorage
        override fun setFromExtensions(extensions: Map<String, String>) {
            val extCpy = HashMap(extensions)
            extCpy.remove("code_challenge")?.let { codeChallenge = CodeChallenge(it, extensions["code_challenge_method"]!!) }
            extCpy.remove("aud")?.let { audience = it }
            extCpy.remove("max_age")?.let { maxAge = it.toLong() }
            extCpy.remove("approved_site")?.let { approvedSiteId = it.toLong() }
            extCpy.remove("login_hint")?.let { loginHint = it }
            extCpy.remove("prompt")?.let { prompts = Prompt.parseSet(it) }
            extCpy.remove("idtoken")?.let { idToken = it }
            extCpy.remove("nonce")?.let { nonce = it }
            extCpy.remove("display")?.let { display = it }
            extCpy.remove("claims")?.let { requestedClaims = oidJson.decodeFromString(it) }
            extCpy.remove("response_mode").let { responseMode = ResponseMode.from(it) }
            this.extensions = extCpy.takeIf { it.isNotEmpty() }
        }
    }

    enum class ResponseMode(val value: String?) {
        DEFAULT(null),
        QUERY("query"),
        FRAGMENT("fragment");

        companion object {
            fun from(value: String?): ResponseMode = when (value) {
                null -> DEFAULT
                "query" -> QUERY
                "fragment" -> FRAGMENT
                else -> throw IllegalArgumentException("Unexpexted response mode: '$value'")
            }
        }
    }

    @Serializable(ClaimsRequestSerializer::class)
    class ClaimsRequest(
        val userInfo: UserInfoRequest?,
        val idToken: IdTokenRequest?
    )

    @OptIn(InternalForStorage::class)
    abstract class ClaimGroupRequest(
        claimRequests: Map<String, ClaimRequest<*>>,
        stringToKey: (String) -> Claim.Key<*>?,
    ) {

        val claimRequests: Map<Claim.Key<*>, ClaimRequest<*>> = claimRequests.mapKeys { (key, _) ->
            stringToKey(key)  ?: Claim.JsonKey(key)
        }


        val sub: ClaimRequest<String>? get() = claimRequests.getClaim(Claim.SUB)
        val name: ClaimRequest<String>? get() = claimRequests.getClaim(Claim.NAME)
        val givenName: ClaimRequest<String>? get() = claimRequests.getClaim(Claim.GIVEN_NAME)
        val familyName: ClaimRequest<String>? get() = claimRequests.getClaim(Claim.FAMILY_NAME)
        val middleName: ClaimRequest<String>? get() = claimRequests.getClaim(Claim.MIDDLE_NAME)
        val nickname: ClaimRequest<String>? get() = claimRequests.getClaim(Claim.NICKNAME)
        val preferredUsername: ClaimRequest<String>? get() = claimRequests.getClaim(Claim.PREFERRED_USERNAME)
        val profile: ClaimRequest<String>? get() = claimRequests.getClaim(Claim.PROFILE)
        val picture: ClaimRequest<String>? get() = claimRequests.getClaim(Claim.PICTURE)
        val website: ClaimRequest<String>? get() = claimRequests.getClaim(Claim.WEBSITE)
        val email: ClaimRequest<String>? get() = claimRequests.getClaim(Claim.EMAIL)
        val emailVerified: ClaimRequest<Boolean>? get() = claimRequests.getClaim(Claim.EMAIL_VERIFIED)
        val gender: ClaimRequest<String>? get() = claimRequests.getClaim(Claim.GENDER)
        val birthdate: ClaimRequest<String>? get() = claimRequests.getClaim(Claim.BIRTHDATE)
        val zoneinfo: ClaimRequest<String>? get() = claimRequests.getClaim(Claim.ZONEINFO)
        val locale: ClaimRequest<String>? get() = claimRequests.getClaim(Claim.LOCALE)
        val phoneNumber: ClaimRequest<String>? get() = claimRequests.getClaim(Claim.PHONE_NUMBER)
        val phoneNumberVerified: ClaimRequest<Boolean>? get() = claimRequests.getClaim(Claim.PHONE_NUMBER_VERIFIED)
        val address: ClaimRequest<DefaultAddress>? get() = claimRequests.getClaim(Claim.ADDRESS)
        val updatedAt: ClaimRequest<Instant>? get() = claimRequests.getClaim(Claim.UPDATED_AT)

        internal open fun toMap(): Map<String, ClaimRequest<JsonElement>> {
            return buildMap {
                for ((key, value) in claimRequests) {
                    put(key.name, key.jsonClaim(value))
                }
            }
        }

    }

    class UserInfoRequest(claimRequests: Map<String, ClaimRequest<*>>) :
        ClaimGroupRequest(claimRequests, { k -> Claim.standardOidInfoClaims[k]})

    @OptIn(InternalForStorage::class)
    class IdTokenRequest(claimRequests: Map<String, ClaimRequest<*>>) : ClaimGroupRequest(
        claimRequests,
        { s -> when (s) {
            "acr" -> Claim.AUTH_CONTEXT_CLASS
            "amr" -> Claim.AUTH_METHOD_REFS
            else -> Claim.standardOidTokenClaims[s] ?: Claim.standardOidInfoClaims[s]
        } }
    ) {

        val acr: ClaimRequest<String>? get() = claimRequests.getClaim(Claim.AUTH_CONTEXT_CLASS)
        val amr: ClaimRequest<List<String>>? get() = claimRequests.getClaim(Claim.AUTH_METHOD_REFS)
    }

    @Serializable
    class ClaimRequest<out T>(
        val essential: Boolean = false,
        val value: T? = null,
        val values: List<T>? = null
    )

}

internal fun <T> MutableMap<String, ClaimRequest<JsonElement>>.removeValue(key: Claim.Key<T>): ClaimRequest<T>? {
    return remove(key.name)?.let { v ->
        ClaimRequest(
            v.essential,
            v.value?.let { key.fromJson(it) },
            v.values?.map { key.fromJson(it) }
        )
    }
}

internal fun <T> Claim.Key<T>.jsonClaim(value: ClaimRequest<*>): ClaimRequest<JsonElement> {
    val v = value as ClaimRequest<T>
    return ClaimRequest(
        v.essential,
        v.value?.let { toJson(it) },
        v.values?.map { toJson(it) }
    )
}

internal fun <T> Map<Claim.Key<*>, ClaimRequest<*>>.jsonClaim(key: Claim.Key<T>): ClaimRequest<JsonElement>? {
    val v = get(key) as ClaimRequest<T>? ?: return null
    return ClaimRequest(
        v.essential,
        v.value?.let { key.toJson(it) },
        v.values?.map { key.toJson(it) }
    )
}

internal fun <T> Map<Claim.Key<*>, ClaimRequest<*>>.getClaim(key: Claim.Key<T>): ClaimRequest<T>? {
    return get(key) as ClaimRequest<T>?
}

internal fun ClaimRequest<JsonElement>.asString(): ClaimRequest<String> {
    return ClaimRequest(
        essential,
        value?.asString(),
        values?.map { it.asString() },
    )
}

internal fun ClaimRequest<JsonElement>.asBoolean(): ClaimRequest<Boolean> {
    return ClaimRequest(
        essential,
        value?.asBoolean(),
        values?.map  { it.asBoolean() } ,
    )
}

internal fun ClaimRequest<JsonElement>.asAddress(): ClaimRequest<DefaultAddress> {
    return ClaimRequest(
        essential,
        value?.let { oidJson.decodeFromJsonElement<DefaultAddress>(it) },
        values?.map  { oidJson.decodeFromJsonElement<DefaultAddress>(it) } ,
    )
}

@JvmName("asJsonFromString")
internal fun ClaimRequest<String>.asJson(): ClaimRequest<JsonElement> {
    return ClaimRequest(
        essential,
        value?.let { JsonPrimitive(it) },
        values?.let { v -> v.map { JsonPrimitive(it) } },
    )
}

@JvmName("asJsonFromBoolean")
internal fun ClaimRequest<Boolean>.asJson(): ClaimRequest<JsonElement> {
    return ClaimRequest(
        essential,
        value?.let { JsonPrimitive(it) },
        values?.let { v -> v.map { JsonPrimitive(it) } },
    )
}

@JvmName("asJsonFromAddress")
internal fun ClaimRequest<DefaultAddress>.asJson(): ClaimRequest<JsonElement> {
    return ClaimRequest(
        essential,
        value?.let { oidJson.encodeToJsonElement(it) },
        values?.let { v -> v.map { oidJson.encodeToJsonElement(it) } },
    )
}

internal object ClaimsRequestSerializer: KSerializer<OpenIdAuthorizationRequest.ClaimsRequest> {
    private val delegate = MapSerializer(String.serializer(), ClaimRequest.serializer(JsonElement.serializer()))

    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("ClaimsRequest") {
        element("userinfo", delegate.descriptor)
        element("id_token", delegate.descriptor)
    }

    override fun serialize(encoder: Encoder, value: OpenIdAuthorizationRequest.ClaimsRequest) {
        encoder.encodeStructure(descriptor) {
            val userInfos = value.userInfo?.toMap()
            if (!userInfos.isNullOrEmpty()) {
                encodeSerializableElement(descriptor, 0, delegate, userInfos)
            }
            val idTokens = value.userInfo?.toMap()
            if (!idTokens.isNullOrEmpty()) {
                encodeSerializableElement(descriptor, 1, delegate, idTokens)
            }
        }
    }

    override fun deserialize(decoder: Decoder): OpenIdAuthorizationRequest.ClaimsRequest {
        return decoder.decodeStructure(descriptor) {
            var userInfo: OpenIdAuthorizationRequest.UserInfoRequest? = null
            var idTokens: OpenIdAuthorizationRequest.IdTokenRequest? = null
            while(true) {
                when(val nextIdx = decodeElementIndex(descriptor)) {
                    CompositeDecoder.DECODE_DONE -> break
                    0 -> userInfo = OpenIdAuthorizationRequest.UserInfoRequest(delegate.deserialize(decoder))
                    1 -> idTokens = OpenIdAuthorizationRequest.IdTokenRequest(delegate.deserialize(decoder))
                    else -> error("Unexpected content in claims request")
                }
            }
            OpenIdAuthorizationRequest.ClaimsRequest(userInfo, idTokens)
        }
    }
}


