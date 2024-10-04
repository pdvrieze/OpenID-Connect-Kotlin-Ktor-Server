package org.mitre.openid.connect

import org.junit.jupiter.api.Assertions.assertInstanceOf

internal inline fun <reified T> assertIs(value: Any?): T {
    return assertInstanceOf(T::class.java, value)
}
