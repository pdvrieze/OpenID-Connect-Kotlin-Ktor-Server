package org.mitre.openid.connect.repository

import org.mitre.openid.connect.model.UserInfo

/**
 * UserInfo repository interface
 *
 * @author Michael Joseph Walsh
 */
interface UserInfoRepository {
    /**
     * Get a UserInfo object by its preferred_username field
     */
    fun getByUsername(username: String): UserInfo?

    /**
     *
     * Get the UserInfo object by its email field
     *
     */
    fun getByEmailAddress(email: String): UserInfo?
}
