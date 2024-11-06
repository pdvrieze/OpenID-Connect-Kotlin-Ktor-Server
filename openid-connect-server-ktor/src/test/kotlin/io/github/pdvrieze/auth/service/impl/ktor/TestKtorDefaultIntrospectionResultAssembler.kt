package io.github.pdvrieze.auth.service.impl.ktor

import io.github.pdvrieze.auth.service.impl.DefaultIntrospectionResultAssembler
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.Authentication
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.SavedUserAuthentication
import org.mitre.oauth2.model.request.AuthorizationRequest
import org.mitre.oauth2.model.request.PlainAuthorizationRequest
import org.mitre.oauth2.service.IntrospectionResultAssembler
import org.mitre.openid.connect.model.UserInfo
import org.mitre.uma.model.Permission
import java.text.ParseException
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

class TestKtorDefaultIntrospectionResultAssembler {
    private val assembler: IntrospectionResultAssembler = DefaultIntrospectionResultAssembler()

    @Test
    @Throws(ParseException::class)
    fun shouldAssembleExpectedResultForAccessToken() {
        // given

        val accessToken = accessToken(
            Instant.ofEpochSecond(123),
            scopes("foo", "bar"), null, "Bearer",
            oauth2AuthenticationWithUser(oauth2Request("clientId"), "name")
        )

        val userInfo = userInfo("sub")

        val authScopes = scopes("foo", "bar", "baz")

        // when
        val result = assembler.assembleFrom(accessToken, userInfo, authScopes)


        // then
        val expected: JsonObject = buildJsonObject {
            put("sub", "sub")
            put("exp", 123L)
            put("expires_at", dateFormat.format(Instant.ofEpochSecond(123)))
            put("scope", "bar foo")
            put("active", true)
            put("user_id", "name")
            put("client_id", "clientId")
            put("token_type", "Bearer")
        }

        Assertions.assertEquals(expected.toSortedMap(), result.toSortedMap())
    }

    @Test
    @Throws(ParseException::class)
    fun shouldAssembleExpectedResultForAccessToken_withPermissions() {
        // given

        val accessToken = accessToken(
            Instant.ofEpochSecond(123),
            scopes("foo", "bar"),
            permissions(permission(1L, "foo", "bar")),
            "Bearer", oauth2AuthenticationWithUser(oauth2Request("clientId"), "name")
        )

        val userInfo = userInfo("sub")

        val authScopes = scopes("foo", "bar", "baz")

        // when
        val result = assembler.assembleFrom(accessToken, userInfo, authScopes)


        // then
        val expected: JsonObject = buildJsonObject {
            put("sub", "sub")
            put("exp", 123L)
            put("expires_at", dateFormat.format(Instant.ofEpochSecond(123)))
            putJsonArray("permissions") {
                addJsonObject {
                    put("resource_set_id", "1")// note that the resource ID comes out as a string
                    putJsonArray("scopes") { add("bar"); add("foo") }
                } // note that scopes are not included if permissions are included
            }
            put("active", true)
            put("user_id", "name")
            put("client_id", "clientId")
            put("token_type", "Bearer")
        }


        Assertions.assertEquals(expected.toSortedMap(), result.toSortedMap())
    }

    @Test
    @Throws(ParseException::class)
    fun shouldAssembleExpectedResultForAccessTokenWithoutUserInfo() {
        // given

        val accessToken = accessToken(
            Instant.ofEpochSecond(123),
            scopes("foo", "bar"), null, "Bearer",
            oauth2AuthenticationWithUser(oauth2Request("clientId"), "name")
        )

        val authScopes = scopes("foo", "bar", "baz")

        // when
        val result = assembler.assembleFrom(accessToken, null, authScopes)


        // then
        val expected: JsonObject = buildJsonObject {
            put("sub", "name")
            put("exp", 123L)
            put("expires_at", dateFormat.format(Instant.ofEpochSecond(123)))
            put("scope", "bar foo")
            put("active", true)
            put("user_id", "name")
            put("client_id", "clientId")
            put("token_type", "Bearer")
        }

        Assertions.assertEquals(expected.toSortedMap(), result.toSortedMap())
    }

    @Test
    fun shouldAssembleExpectedResultForAccessTokenWithoutExpiry() {
        // given

        val accessToken = accessToken(
            null, scopes("foo", "bar"), null, "Bearer",
            oauth2AuthenticationWithUser(oauth2Request("clientId"), "name")
        )

        val userInfo = userInfo("sub")

        val authScopes = scopes("foo", "bar", "baz")

        // when
        val result = assembler.assembleFrom(accessToken, userInfo, authScopes)


        // then
        val expected: JsonObject = buildJsonObject {
            put("sub", "sub")
            put("scope", "bar foo")
            put("active", true)
            put("user_id", "name")
            put("client_id", "clientId")
            put("token_type", "Bearer")
        }

        Assertions.assertEquals(expected.toSortedMap(), result.toSortedMap())
    }

    @Test
    @Throws(ParseException::class)
    fun shouldAssembleExpectedResultForAccessTokenWithoutUserAuthentication() {
        // given
        val accessToken = accessToken(
            Instant.ofEpochSecond(123),
            scopes("foo", "bar"), null, "Bearer",
            oauth2Authentication(oauth2Request("clientId"), null)
        )

        val authScopes = scopes("foo", "bar", "baz")

        // when
        val result = assembler.assembleFrom(accessToken, null, authScopes)


        // then `user_id` should not be present
        val expected: JsonObject = buildJsonObject {
            put("sub", "clientId")
            put("exp", 123L)
            put("expires_at", dateFormat.format(Instant.ofEpochSecond(123)))
            put("scope", "bar foo")
            put("active", true)
            put("client_id", "clientId")
            put("token_type", "Bearer")
        }


        Assertions.assertEquals(expected.toSortedMap(), result.toSortedMap())
    }

    @Test
    @Throws(ParseException::class)
    fun shouldAssembleExpectedResultForRefreshToken() {
        // given

        val refreshToken = refreshToken(
            Instant.ofEpochSecond(123),
            oauth2AuthenticationWithUser(oauth2Request("clientId", scopes("foo", "bar")), "name")
        )

        val userInfo = userInfo("sub")

        val authScopes = scopes("foo", "bar", "baz")

        // when
        val result = assembler.assembleFrom(refreshToken, userInfo, authScopes)


        // then
        val expected: JsonObject = buildJsonObject {
            put("sub", "sub")
            put("exp", 123L)
            put("expires_at", dateFormat.format(Instant.ofEpochSecond(123)))
            put("scope", "bar foo")
            put("active", true)
            put("user_id", "name")
            put("client_id", "clientId")
        }

        Assertions.assertEquals(expected.toSortedMap(), result.toSortedMap())
    }

    @Test
    @Throws(ParseException::class)
    fun shouldAssembleExpectedResultForRefreshTokenWithoutUserInfo() {
        // given

        val refreshToken = refreshToken(
            Instant.ofEpochSecond(123),
            oauth2AuthenticationWithUser(oauth2Request("clientId", scopes("foo", "bar")), "name")
        )

        val authScopes = scopes("foo", "bar", "baz")

        // when
        val result = assembler.assembleFrom(refreshToken, null, authScopes)

        // then
        val expected: JsonObject = buildJsonObject {
            put("sub", "name")
            put("exp", 123L)
            put("expires_at", dateFormat.format(Instant.ofEpochSecond(123)))
            put("scope", "bar foo")
            put("active", true)
            put("user_id", "name")
            put("client_id", "clientId")
        }

        Assertions.assertEquals(expected.toSortedMap(), result.toSortedMap())
    }

    @Test
    fun shouldAssembleExpectedResultForRefreshTokenWithoutExpiry() {
        // given

        val refreshToken = refreshToken(
            null,
            oauth2AuthenticationWithUser(oauth2Request("clientId", scopes("foo", "bar")), "name")
        )

        val userInfo = userInfo("sub")

        val authScopes = scopes("foo", "bar", "baz")

        // when
        val result = assembler.assembleFrom(refreshToken, userInfo, authScopes)


        // then
        val expected: JsonObject = buildJsonObject {
            put("sub", "sub")
            put("scope", "bar foo")
            put("active", true)
            put("user_id", "name")
            put("client_id", "clientId")
        }

        Assertions.assertEquals(expected.toSortedMap(), result.toSortedMap())
    }

    @Test
    @Throws(ParseException::class)
    fun shouldAssembleExpectedResultForRefreshTokenWithoutUserAuthentication() {
        // given
        val refreshToken = refreshToken(
            null,
            oauth2Authentication(oauth2Request("clientId", scopes("foo", "bar")), null)
        )

        val authScopes = scopes("foo", "bar", "baz")

        // when
        val result = assembler.assembleFrom(refreshToken, null, authScopes)


        // then `user_id` should not be present
        val expected: JsonObject = buildJsonObject {
            put("sub", "clientId")
            put("scope", "bar foo")
            put("active", true)
            put("client_id", "clientId")
        }

        Assertions.assertEquals(expected.toSortedMap(), result.toSortedMap())
    }


    private fun userInfo(sub: String): UserInfo {
        val userInfo = org.mockito.kotlin.mock<UserInfo>()
        org.mockito.kotlin.given(userInfo.subject).willReturn(sub)
        return userInfo
    }

    private fun accessToken(
        exp: Instant?,
        scopes: Set<String>,
        permissions: Set<Permission>?,
        tokenType: String,
        authentication: AuthenticatedAuthorizationRequest
    ): OAuth2AccessTokenEntity {
        return org.mockito.kotlin.mock<OAuth2AccessTokenEntity>(defaultAnswer = org.mockito.Mockito.RETURNS_DEEP_STUBS).also {
            org.mockito.kotlin.given(it.expirationInstant).willReturn(exp ?: Instant.MIN)
            org.mockito.kotlin.given(it.scope).willReturn(scopes)
            org.mockito.kotlin.given(it.permissions).willReturn(permissions)
            org.mockito.kotlin.given(it.tokenType).willReturn(tokenType)
            org.mockito.kotlin.given(it.authenticationHolder.authenticatedAuthorizationRequest).willReturn(authentication)
        }
    }

    private fun refreshToken(exp: Instant?, authentication: AuthenticatedAuthorizationRequest): OAuth2RefreshTokenEntity {
        org.mockito.kotlin.mock<OAuth2AccessTokenEntity>(defaultAnswer = org.mockito.Mockito.RETURNS_DEEP_STUBS)
        return org.mockito.kotlin.mock<OAuth2RefreshTokenEntity>(defaultAnswer = org.mockito.Mockito.RETURNS_DEEP_STUBS)
            .apply {
            org.mockito.kotlin.given(expirationInstant).willReturn(exp ?: Instant.MIN)
            org.mockito.kotlin.given(authenticationHolder.authenticatedAuthorizationRequest).willReturn(authentication)
        }
    }

    private fun oauth2AuthenticationWithUser(request: AuthorizationRequest, username: String): AuthenticatedAuthorizationRequest {
        val userAuthentication = object : Authentication {
            override val name: String get() = username
            override val authorities: Collection<GrantedAuthority> get() = emptySet()
            override val isAuthenticated: Boolean get() = true
        }
        return oauth2Authentication(request, userAuthentication)
    }

    private fun oauth2Authentication(
        request: AuthorizationRequest,
        userAuthentication: Authentication?
    ): AuthenticatedAuthorizationRequest {
        return AuthenticatedAuthorizationRequest(request, userAuthentication?.let { SavedUserAuthentication.from(it) })
    }

    private fun oauth2Request(clientId: String, scopes: Set<String>? = null): AuthorizationRequest {
        val now = Instant.now()
        return PlainAuthorizationRequest.Builder(clientId = clientId).also { b ->
            b.approval = AuthorizationRequest.Approval(now)
            b.scope = scopes ?: emptySet()
            b.requestTime = now
        }.build()
    }

    private fun scopes(vararg scopes: String): Set<String> {
        return scopes.toHashSet()
    }

    private fun permissions(vararg permissions: Permission): Set<Permission> {
        return permissions.toHashSet()
    }

    private fun permission(resourceSetId: Long, vararg scopes: String): Permission {
        val permission = org.mockito.kotlin.mock<Permission>(defaultAnswer = org.mockito.Mockito.RETURNS_DEEP_STUBS)
        org.mockito.kotlin.given(permission.resourceSet.id).willReturn(resourceSetId)
        org.mockito.kotlin.given(permission.scopes).willReturn(scopes(*scopes))
        return permission
    }

    companion object {
        val dateFormat: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssZ")
            .withZone(ZoneOffset.UTC)
    }
}
