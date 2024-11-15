package org.mitre.oauth2.repository

import org.mitre.data.PageCriteria
import org.mitre.oauth2.model.AuthorizationCodeEntity

/**
 * Interface for saving and consuming OAuth2 authorization codes as AuthorizationCodeEntitys.
 *
 * @author aanganes
 */
interface AuthorizationCodeRepository {
    /**
     * Save an AuthorizationCodeEntity to the repository
     *
     * @param authorizationCode the AuthorizationCodeEntity to save
     * @return                    the saved AuthorizationCodeEntity
     */
    fun save(authorizationCode: AuthorizationCodeEntity): AuthorizationCodeEntity?

    /**
     * Get an authorization code from the repository by value.
     *
     * @param code                        the authorization code value
     * @return                            the authentication associated with the code
     */
    fun getByCode(code: String): AuthorizationCodeEntity?

    /**
     * Remove an authorization code from the repository
     *
     */
    fun remove(authorizationCodeEntity: AuthorizationCodeEntity)

    /**
     * @return A collection of all expired codes.
     */
	val expiredCodes: Collection<AuthorizationCodeEntity>

    /**
     * @return A collection of all expired codes, limited by the given
     * PageCriteria.
     */
    fun getExpiredCodes(pageCriteria: PageCriteria): Collection<AuthorizationCodeEntity>
}

