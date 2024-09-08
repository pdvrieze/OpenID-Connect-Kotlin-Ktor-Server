package org.mitre.oauth2.util

import java.security.SecureRandom
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

@OptIn(ExperimentalContracts::class)
fun Long?.requireId(): Long {
    contract {
        returns() implies (this@requireId != null)
    }
    return requireNotNull(this) {"Missing id"}
}

@Deprecated("No need, is already not null", ReplaceWith("this"))
fun Long.requireId(): Long = this

@OptIn(ExperimentalEncodingApi::class)
class RandomStringGenerator(
    val length: Int  = 6,
    private val random: SecureRandom = SecureRandom()
) {

    fun generate(): String {
        return Base64.UrlSafe.encode(ByteArray(length).also { random.nextBytes(it) })
    }

}
