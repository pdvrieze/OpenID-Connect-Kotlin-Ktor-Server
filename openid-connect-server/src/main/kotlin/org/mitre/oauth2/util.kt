package org.mitre.oauth2.util

import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract

@OptIn(ExperimentalContracts::class)
fun Long?.requireId(): Long {
    contract {
        returns() implies (this@requireId != null)
    }
    return requireNotNull(this) {"Missing id"}
}

@Deprecated("No need, is already not null", ReplaceWith("this"))
fun Long.requireId(): Long = this
