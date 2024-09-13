package org.mitre.openid.connect.util

import org.junit.jupiter.api.Assertions.assertInstanceOf

inline fun <reified T> assertIs(value: Any?): T {
    return assertInstanceOf(T::class.java, value)
}
