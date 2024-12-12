package io.github.pdvrieze.auth

import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.openid.connect.model.convert.ISOInstant

class SavedAuthentication(
    val principalName: String,
    id: Long? = null,
    override val authTime: ISOInstant,
    authorities: Collection<GrantedAuthority> = emptyList(),
    val scope: Set<String> = emptySet(),
    sourceClass: String? = null,
) : Authentication {

    var id: Long? = id

    override var authorities: Set<GrantedAuthority> = authorities.toHashSet()
        private set

    var sourceClass: String? = sourceClass

    // TODO (actually recover the scope)
    override fun hasScope(scope: String): Boolean = scope in this.scope

    /**
     * Create a Saved Auth from an existing Auth token
     */
    constructor(src: UserAuthentication) : this(
        principalName = src.userId,
        id = null,
        authTime = src.authTime,
        authorities = src.authorities,
        // if we're copying in a saved auth, carry over the original class name
        scope = (src as? ScopedAuthentication)?.scopes ?: emptySet(),
        sourceClass = src.javaClass.name,
    )

    /**
     * Create a Saved Auth from an existing Auth token
     */
    constructor(src: ClientAuthentication) : this(
        principalName = src.clientId,
        id = null,
        authTime = src.authTime,
        authorities = setOf(GrantedAuthority.ROLE_CLIENT),
        // if we're copying in a saved auth, carry over the original class name
        scope = (src as? ScopedAuthentication)?.scopes ?: emptySet(),
        sourceClass = src.javaClass.name,
    )

    /**
     * Create a Saved Auth from an existing Auth token
     */
    constructor(src: TokenAuthentication) : this(
        principalName = src.principalName,
        id = null,
        authTime = src.authTime,
        authorities = src.authorities,
        // if we're copying in a saved auth, carry over the original class name
        scope = (src as? ScopedAuthentication)?.scopes ?: emptySet(),
        sourceClass = src.javaClass.name,
    )

    companion object {
        private const val serialVersionUID = -1804249963940323488L

        fun from(src: Authentication): SavedAuthentication = when(src) {
            is SavedAuthentication -> src
            is ClientAuthentication -> SavedAuthentication(src)
            is UserAuthentication -> SavedAuthentication(src)
            is TokenAuthentication -> SavedAuthentication(src)
        }
    }
}
