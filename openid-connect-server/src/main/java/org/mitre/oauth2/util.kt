package org.mitre.oauth2.util

fun Long?.toJavaId(): java.lang.Long {
    return java.lang.Long(requireNotNull(this) {"Missing id"})
}
