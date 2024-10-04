package org.mitre.openid.connect.repository

import org.mitre.openid.connect.model.Address

/**
 * Address repository interface
 *
 * @author Michael Joseph Walsh
 */
interface AddressRepository {
    /**
     * Returns the Address for the given id
     *
     * id the id of the Address
     * @return a valid Address if it exists, null otherwise
     */
    fun getById(id: Long): Address?
}
