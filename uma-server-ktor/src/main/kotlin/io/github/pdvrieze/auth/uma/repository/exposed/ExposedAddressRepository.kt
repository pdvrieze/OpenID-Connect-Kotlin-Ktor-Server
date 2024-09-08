package io.github.pdvrieze.auth.uma.repository.exposed

import io.github.pdvrieze.auth.exposed.RepositoryBase
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.selectAll
import org.mitre.openid.connect.model.Address
import org.mitre.openid.connect.model.DefaultAddress
import org.mitre.openid.connect.repository.AddressRepository

class ExposedAddressRepository(database: Database) : RepositoryBase(database, Addresses), AddressRepository {
    override fun getById(id: Long): Address {
        return Addresses.selectAll().where { Addresses.id eq id }
            .map { r ->
                DefaultAddress(
                    id = r[Addresses.id].value,
                    formatted = r[Addresses.formatted],
                    streetAddress = r[Addresses.streetAddress],
                    locality = r[Addresses.locality],
                    region = r[Addresses.region],
                    postalCode = r[Addresses.postalCode],
                    country = r[Addresses.country],
                )
            }.single()
    }
}
