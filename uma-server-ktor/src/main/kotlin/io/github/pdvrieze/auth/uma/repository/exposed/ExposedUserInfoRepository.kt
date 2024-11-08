package io.github.pdvrieze.auth.uma.repository.exposed

import io.github.pdvrieze.auth.exposed.RepositoryBase
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.Transaction
import org.jetbrains.exposed.sql.selectAll
import org.mitre.openid.connect.model.Address
import org.mitre.openid.connect.model.DefaultAddress
import org.mitre.openid.connect.model.DefaultUserInfo
import org.mitre.openid.connect.model.UserInfo
import org.mitre.openid.connect.repository.UserInfoRepository
import org.mitre.util.oidJson

class ExposedUserInfoRepository(database: Database) :
    RepositoryBase(database, UserInfos), UserInfoRepository {

    override fun getByUsername(username: String): UserInfo? = transaction {
        UserInfos
            .selectAll().where { UserInfos.name eq username  }
            .singleOrNull()
            ?.let { r ->
                val addr = r[UserInfos.addressId]?.toLongOrNull()?.let { addrId -> getAddress(addrId) }
                r.toUserInfo(addr)
            }
    }

    private fun Transaction.getAddress(addrId: Long) = Addresses.selectAll()
        .where { Addresses.id eq addrId }
        .singleOrNull()
        ?.toAddress()

    override fun getByEmailAddress(email: String): UserInfo? = transaction {
        UserInfos.selectAll().where { UserInfos.email eq email }.singleOrNull()?.let { r ->
            val addr = r[UserInfos.addressId]?.toLongOrNull()?.let { addrId -> getAddress(addrId) }
            r.toUserInfo(addr)
        }
    }
}

internal fun ResultRow.toAddress(): Address {
    val r = this
    return with(Addresses) {
        DefaultAddress(
            id = r[id].value,
            formatted = r[formatted],
            streetAddress = r[streetAddress],
            locality = r[locality],
            region = r[region],
            postalCode = r[postalCode],
            country = r[country],
        )
    }
}

internal fun ResultRow.toUserInfo(address: Address?): UserInfo {
    val r = this
    with(UserInfos) {
        return DefaultUserInfo(
            id = r[id].value,
            subject = r[sub],
            preferredUsername = r[preferredUsername],
            name = r[name],
            givenName = r[givenName],
            familyName = r[familyName],
            middleName = r[middleName],
            nickname = r[nickname],
            profile = r[profile],
            picture = r[picture],
            website = r[website],
            email = r[email],
            emailVerified = r[emailVerified],
            gender = r[gender],
            zoneinfo = r[zoneInfo],
            locale = r[locale],
            phoneNumber = r[phoneNumber],
            phoneNumberVerified = r[phoneNumberVerified],
            _address = address?.let { DefaultAddress.from(it) },
            updatedTime = r[updatedTime],
            birthdate = r[birthdate],
            source = r[src]?.let { oidJson.parseToJsonElement(it).jsonObject },
        )
    }

}
