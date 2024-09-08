package io.github.pdvrieze.auth.service.impl

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.mitre.oauth2.model.Authentication
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2Authentication
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.SavedUserAuthentication
import org.mitre.oauth2.model.convert.OAuth2Request
import org.mitre.oauth2.service.IntrospectionResultAssembler
import org.mitre.openid.connect.model.UserInfo
import org.mitre.uma.model.Permission
import java.text.ParseException
import java.text.SimpleDateFormat
import java.util.*
import javax.swing.text.DateFormatter

class TestDefaultIntrospectionResultAssembler {
    private val assembler: IntrospectionResultAssembler = DefaultIntrospectionResultAssembler()

    @Test
    @Throws(ParseException::class)
    fun shouldAssembleExpectedResultForAccessToken() {
        // given

        val accessToken = accessToken(
            Date(123 * 1000L), scopes("foo", "bar"), null, "Bearer",
            oauth2AuthenticationWithUser(oauth2Request("clientId"), "name")
        )

        val userInfo = userInfo("sub")

        val authScopes = scopes("foo", "bar", "baz")

        // when
        val result = assembler.assembleFrom(accessToken, userInfo, authScopes)


        // then
        val expected = mapOf(
            "sub" to "sub",
            "exp" to 123L,
            "expires_at" to dateFormat.valueToString(Date(123 * 1000L)),
            "scope" to "bar foo",
            "active" to true,
            "user_id" to "name",
            "client_id" to "clientId",
            "token_type" to "Bearer",
        )
        Assertions.assertEquals(expected, result)
    }

    @Test
    @Throws(ParseException::class)
    fun shouldAssembleExpectedResultForAccessToken_withPermissions() {
        // given

        val accessToken = accessToken(
            Date(123 * 1000L), scopes("foo", "bar"),
            permissions(permission(1L, "foo", "bar")),
            "Bearer", oauth2AuthenticationWithUser(oauth2Request("clientId"), "name")
        )

        val userInfo = userInfo("sub")

        val authScopes = scopes("foo", "bar", "baz")

        // when
        val result = assembler.assembleFrom(accessToken, userInfo, authScopes)


        // then
        val expected: Map<String, Any> = hashMapOf(
            ("sub" to "sub"),
            ("exp" to 123L),
            ("expires_at" to dateFormat.valueToString(Date(123 * 1000L))),
            ("permissions" to hashSetOf(
                mapOf(
                    "resource_set_id" to "1", // note that the resource ID comes out as a string
                    "scopes" to hashSetOf("bar", "foo")
                )
            )), // note that scopes are not included if permissions are included
            "active" to true,
            "user_id" to "name",
            "client_id" to "clientId",
            "token_type" to "Bearer",
        )
        Assertions.assertEquals(expected, result)
    }

    @Test
    @Throws(ParseException::class)
    fun shouldAssembleExpectedResultForAccessTokenWithoutUserInfo() {
        // given

        val accessToken = accessToken(
            Date(123 * 1000L), scopes("foo", "bar"), null, "Bearer",
            oauth2AuthenticationWithUser(oauth2Request("clientId"), "name")
        )

        val authScopes = scopes("foo", "bar", "baz")

        // when
        val result = assembler.assembleFrom(accessToken, null, authScopes)


        // then
        val expected: Map<String, Any> = mapOf(
            "sub" to "name",
            "exp" to 123L,
            "expires_at" to dateFormat.valueToString(Date(123 * 1000L)),
            "scope" to "bar foo",
            "active" to true,
            "user_id" to "name",
            "client_id" to "clientId",
            "token_type" to "Bearer",
        )

        Assertions.assertEquals(expected, result)
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
        val expected: Map<String, Any> = mapOf(
            "sub" to "sub",
            "scope" to "bar foo",
            "active" to true,
            "user_id" to "name",
            "client_id" to "clientId",
            "token_type" to "Bearer",

        )

        Assertions.assertEquals(expected, result)
    }

    @Test
    @Throws(ParseException::class)
    fun shouldAssembleExpectedResultForAccessTokenWithoutUserAuthentication() {
        // given
        val accessToken = accessToken(
            Date(123 * 1000L), scopes("foo", "bar"), null, "Bearer",
            oauth2Authentication(oauth2Request("clientId"), null)
        )

        val authScopes = scopes("foo", "bar", "baz")

        // when
        val result = assembler.assembleFrom(accessToken, null, authScopes)


        // then `user_id` should not be present
        val expected: Map<String, Any> = mapOf(
            "sub" to "clientId",
            "exp" to 123L,
            "expires_at" to dateFormat.valueToString(Date(123 * 1000L)),
            "scope" to "bar foo",
            "active" to true,
            "client_id" to "clientId",
            "token_type" to "Bearer",
        )

        Assertions.assertEquals(expected, result)
    }

    @Test
    @Throws(ParseException::class)
    fun shouldAssembleExpectedResultForRefreshToken() {
        // given

        val refreshToken = refreshToken(
            Date(123 * 1000L),
            oauth2AuthenticationWithUser(oauth2Request("clientId", scopes("foo", "bar")), "name")
        )

        val userInfo = userInfo("sub")

        val authScopes = scopes("foo", "bar", "baz")

        // when
        val result = assembler.assembleFrom(refreshToken, userInfo, authScopes)


        // then
        val expected: Map<String, Any> = mapOf(
            "sub" to "sub",
            "exp" to 123L,
            "expires_at" to dateFormat.valueToString(Date(123 * 1000L)),
            "scope" to "bar foo",
            "active" to true,
            "user_id" to "name",
            "client_id" to "clientId",

            )

        Assertions.assertEquals(expected, result)
    }

    @Test
    @Throws(ParseException::class)
    fun shouldAssembleExpectedResultForRefreshTokenWithoutUserInfo() {
        // given

        val refreshToken = refreshToken(
            Date(123 * 1000L),
            oauth2AuthenticationWithUser(oauth2Request("clientId", scopes("foo", "bar")), "name")
        )

        val authScopes = scopes("foo", "bar", "baz")

        // when
        val result = assembler.assembleFrom(refreshToken, null, authScopes)

        // then
        val expected: Map<String, Any> = mapOf(
            "sub" to "name",
            "exp" to 123L,
            "expires_at" to dateFormat.valueToString(Date(123 * 1000L)),
            "scope" to "bar foo",
            "active" to true,
            "user_id" to "name",
            "client_id" to "clientId",
        )

        Assertions.assertEquals(expected, result)
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
        val expected: Map<String, Any> = mapOf(
            "sub" to "sub",
            "scope" to "bar foo",
            "active" to true,
            "user_id" to "name",
            "client_id" to "clientId",
        )

        Assertions.assertEquals(expected, result)
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
        val expected: Map<String, Any> = mapOf(
            "sub" to "clientId",
            "scope" to "bar foo",
            "active" to true,
            "client_id" to "clientId",
        )

        Assertions.assertEquals(expected, result)
    }


    private fun userInfo(sub: String): UserInfo {
        val userInfo = org.mockito.kotlin.mock<UserInfo>()
        org.mockito.kotlin.given(userInfo.sub).willReturn(sub)
        return userInfo
    }

    private fun accessToken(
        exp: Date?,
        scopes: Set<String>,
        permissions: Set<Permission>?,
        tokenType: String,
        authentication: OAuth2Authentication
    ): OAuth2AccessTokenEntity {
        return org.mockito.kotlin.mock<OAuth2AccessTokenEntity>(defaultAnswer = org.mockito.Mockito.RETURNS_DEEP_STUBS).also {
            org.mockito.kotlin.given(it.expiration).willReturn(exp)
            org.mockito.kotlin.given(it.scope).willReturn(scopes)
            org.mockito.kotlin.given(it.permissions).willReturn(permissions)
            org.mockito.kotlin.given(it.tokenType).willReturn(tokenType)
            org.mockito.kotlin.given(it.authenticationHolder.authentication).willReturn(authentication)
        }
    }

    private fun refreshToken(exp: Date?, authentication: OAuth2Authentication): OAuth2RefreshTokenEntity {
        org.mockito.kotlin.mock<OAuth2AccessTokenEntity>(defaultAnswer = org.mockito.Mockito.RETURNS_DEEP_STUBS)
        return org.mockito.kotlin.mock<OAuth2RefreshTokenEntity>(defaultAnswer = org.mockito.Mockito.RETURNS_DEEP_STUBS)
            .apply {
            org.mockito.kotlin.given(expiration).willReturn(exp)
            org.mockito.kotlin.given(authenticationHolder.authentication).willReturn(authentication)
        }
    }

    private fun oauth2AuthenticationWithUser(request: OAuth2Request, username: String): OAuth2Authentication {
        val userAuthentication = object : Authentication {
            override val name: String get() = username
            override val authorities: Collection<GrantedAuthority> get() = emptySet()
            override val isAuthenticated: Boolean get() = true
        }
        return oauth2Authentication(request, userAuthentication)
    }

    private fun oauth2Authentication(
        request: OAuth2Request,
        userAuthentication: Authentication?
    ): OAuth2Authentication {
        return OAuth2Authentication(request, userAuthentication?.let { SavedUserAuthentication.from(it) })
    }

    private fun oauth2Request(clientId: String, scopes: Set<String>? = null): OAuth2Request {
        return OAuth2Request(
            requestParameters = emptyMap(),
            clientId = clientId,
            authorities = emptySet(),
            isApproved = true,
            scope = emptySet(),
            resourceIds = null,
            redirectUri = null,
            responseTypes = null,
            extensionStrings = null
        )
    }

    private fun scopes(vararg scopes: String): Set<String> {
        return scopes.toHashSet()
    }

    private fun permissions(vararg permissions: Permission): Set<Permission> {
        return permissions.toHashSet()
    }

    private fun permission(resourceSetId: Long, vararg scopes: String): Permission {
        val permission = org.mockito.kotlin.mock<Permission>(defaultAnswer = org.mockito.Mockito.RETURNS_DEEP_STUBS)
        org.mockito.kotlin.given(permission.resourceSet!!.id).willReturn(resourceSetId)
        org.mockito.kotlin.given(permission.scopes).willReturn(scopes(*scopes))
        return permission
    }

    companion object {
        private val dateFormat = DateFormatter(SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ"))
    }
}
