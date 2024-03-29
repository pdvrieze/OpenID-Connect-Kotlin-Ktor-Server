package org.mitre.oauth2.util

import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract

@OptIn(ExperimentalContracts::class)
fun Long?.toJavaId(): java.lang.Long {
    contract {
        returns() implies (this@toJavaId != null)
    }
    return java.lang.Long(requireNotNull(this) {"Missing id"})
}
