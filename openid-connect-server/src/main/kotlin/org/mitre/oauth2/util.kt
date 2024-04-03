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

