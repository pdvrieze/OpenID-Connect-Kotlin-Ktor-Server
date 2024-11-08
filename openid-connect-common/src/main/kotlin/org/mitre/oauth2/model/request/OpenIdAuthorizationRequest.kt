package org.mitre.oauth2.model.request

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
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
import kotlinx.serialization.json.jsonPrimitive
import org.mitre.oauth2.model.request.OpenIdAuthorizationRequest.ClaimRequest
import org.mitre.openid.connect.model.Address
import org.mitre.openid.connect.model.DefaultAddress
import org.mitre.openid.connect.request.Prompt
import org.mitre.util.asBoolean
import org.mitre.util.asString
import org.mitre.util.oidJson

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

    abstract class ClaimGroupRequest(
        val sub: ClaimRequest<String>?,
        val name: ClaimRequest<String>?,
        @SerialName("given_name") val givenName: ClaimRequest<String>?,
        @SerialName("family_name") val familyName: ClaimRequest<String>?,
        @SerialName("middle_name") val middleName: ClaimRequest<String>?,
        val nickname: ClaimRequest<String>?,
        @SerialName("preferred_username") val preferredUsername: ClaimRequest<String>?,
        val profile: ClaimRequest<String>?,
        val picture: ClaimRequest<String>?,
        val website: ClaimRequest<String>?,
        val email: ClaimRequest<String>?,
        @SerialName("email_verified") val emailVerified: ClaimRequest<Boolean>?,
        val gender: ClaimRequest<String>?,
        val birthdate: ClaimRequest<String>?,
        val zoneinfo: ClaimRequest<String>?,
        val locale: ClaimRequest<String>?,
        @SerialName("phone_number") val phoneNumber: ClaimRequest<String>?,
        @SerialName("phone_number_verified") val phoneNumberVerified: ClaimRequest<Boolean>?,
        val address: ClaimRequest<DefaultAddress>?,
        @SerialName("updated_at") val updatedAt: ClaimRequest<String>?,
    ) {

        abstract val otherClaimRequests: Map<String, ClaimRequest<JsonElement>>

        constructor(claimRequests: MutableMap<String, ClaimRequest<JsonElement>>): this(
            claimRequests.remove("sub")?.asString(),
            claimRequests.remove("name")?.asString(),
            claimRequests.remove("given_name")?.asString(),
            claimRequests.remove("family_name")?.asString(),
            claimRequests.remove("middle_name")?.asString(),
            claimRequests.remove("nickname")?.asString(),
            claimRequests.remove("preferred_username")?.asString(),
            claimRequests.remove("profile")?.asString(),
            claimRequests.remove("picture")?.asString(),
            claimRequests.remove("website")?.asString(),
            claimRequests.remove("email")?.asString(),
            claimRequests.remove("email_verified")?.asBoolean(),
            claimRequests.remove("gender")?.asString(),
            claimRequests.remove("birthdate")?.asString(),
            claimRequests.remove("zoneinfo")?.asString(),
            claimRequests.remove("locale")?.asString(),
            claimRequests.remove("phone_number")?.asString(),
            claimRequests.remove("phone_number_verified")?.asBoolean(),
            claimRequests.remove("address")?.asAddress(),
            claimRequests.remove("updated_at")?.asString(),
        )

        internal open fun toMap(): Map<String, ClaimRequest<JsonElement>> {
            return buildMap {
                if (sub != null) put("sub", sub.asJson())
                if (name != null) put("name", name.asJson())
                if (givenName != null) put("given_name", givenName.asJson())
                if (familyName != null) put("family_name", familyName.asJson())
                if (middleName != null) put("middle_name", middleName.asJson())
                if (nickname != null) put("nickname", nickname.asJson())
                if (preferredUsername != null) put("preferred_username", preferredUsername.asJson())
                if (profile != null) put("profile", profile.asJson())
                if (picture != null) put("picture", picture.asJson())
                if (website != null) put("website", website.asJson())
                if (email != null) put("email", email.asJson())
                if (emailVerified != null) put("email_verified", emailVerified.asJson())
                if (gender != null) put("gender", gender.asJson())
                if (birthdate != null) put("birthdate", birthdate.asJson())
                if (zoneinfo != null) put("zoneinfo", zoneinfo.asJson())
                if (locale != null) put("locale", locale.asJson())
                if (phoneNumber != null) put("phone_number", phoneNumber.asJson())
                if (phoneNumberVerified != null) put("phone_number_verified", phoneNumberVerified.asJson())
                if (address != null) put("address", address.asJson())
                if (updatedAt != null) put("updated_at", updatedAt.asJson())

                putAll(otherClaimRequests)
            }
        }

    }

    class UserInfoRequest : ClaimGroupRequest {
        override val otherClaimRequests: Map<String, ClaimRequest<JsonElement>>

        constructor(
            sub: ClaimRequest<String>?,
            name: ClaimRequest<String>?,
            givenName: ClaimRequest<String>?,
            familyName: ClaimRequest<String>?,
            middleName: ClaimRequest<String>?,
            nickname: ClaimRequest<String>?,
            preferredUsername: ClaimRequest<String>?,
            profile: ClaimRequest<String>?,
            picture: ClaimRequest<String>?,
            website: ClaimRequest<String>?,
            email: ClaimRequest<String>?,
            emailVerified: ClaimRequest<Boolean>?,
            gender: ClaimRequest<String>?,
            birthdate: ClaimRequest<String>?,
            zoneinfo: ClaimRequest<String>?,
            locale: ClaimRequest<String>?,
            phoneNumber: ClaimRequest<String>?,
            phoneNumberVerified: ClaimRequest<Boolean>?,
            address: ClaimRequest<DefaultAddress>?,
            updatedAt: ClaimRequest<String>?,
            otherClaimRequests: Map<String, ClaimRequest<JsonElement>>
        ) : super(sub, name, givenName, familyName, middleName, nickname, preferredUsername, profile, picture, website, email, emailVerified, gender, birthdate, zoneinfo, locale, phoneNumber, phoneNumberVerified, address, updatedAt) {
            this.otherClaimRequests = otherClaimRequests
        }

        constructor(requests: MutableMap<String, ClaimRequest<JsonElement>>) : super(requests) {
            this.otherClaimRequests = requests.toMap()
        }
    }

    class IdTokenRequest : ClaimGroupRequest {

        val acr: ClaimRequest<String>?
        val amr: ClaimRequest<JsonElement>?

        override val otherClaimRequests: Map<String, ClaimRequest<JsonElement>>

        constructor(
            sub: ClaimRequest<String>?,
            name: ClaimRequest<String>?,
            givenName: ClaimRequest<String>?,
            familyName: ClaimRequest<String>?,
            middleName: ClaimRequest<String>?,
            nickname: ClaimRequest<String>?,
            preferredUsername: ClaimRequest<String>?,
            profile: ClaimRequest<String>?,
            picture: ClaimRequest<String>?,
            website: ClaimRequest<String>?,
            email: ClaimRequest<String>?,
            emailVerified: ClaimRequest<Boolean>?,
            gender: ClaimRequest<String>?,
            birthdate: ClaimRequest<String>?,
            zoneinfo: ClaimRequest<String>?,
            locale: ClaimRequest<String>?,
            phoneNumber: ClaimRequest<String>?,
            phoneNumberVerified: ClaimRequest<Boolean>?,
            address: ClaimRequest<DefaultAddress>?,
            updatedAt: ClaimRequest<String>?,
            acr: ClaimRequest<String>?,
            amr: ClaimRequest<JsonElement>?,
            otherClaimRequests: Map<String, ClaimRequest<JsonElement>>
        ) : super(sub, name, givenName, familyName, middleName, nickname, preferredUsername, profile, picture, website, email, emailVerified, gender, birthdate, zoneinfo, locale, phoneNumber, phoneNumberVerified, address, updatedAt) {
            this.otherClaimRequests = otherClaimRequests
            this.acr = acr
            this.amr = amr
        }

        constructor(requests: MutableMap<String, ClaimRequest<JsonElement>>) : super(requests) {
            acr = requests.remove("acr")?.asString()
            amr = requests.remove("amr")
            this.otherClaimRequests = requests.toMap()
        }

    }

    @Serializable
    class ClaimRequest<T>(
        val essential: Boolean = false,
        val value: T? = null,
        val values: List<T>? = null
    )

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
                    0 -> userInfo = OpenIdAuthorizationRequest.UserInfoRequest(delegate.deserialize(decoder) as MutableMap)
                    1 -> idTokens = OpenIdAuthorizationRequest.IdTokenRequest(delegate.deserialize(decoder) as MutableMap)
                    else -> error("Unexpected content in claims request")
                }
            }
            OpenIdAuthorizationRequest.ClaimsRequest(userInfo, idTokens)
        }
    }
}


