package io.github.pdvrieze.test.util

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive


internal val JsonElement?.asString: String?
    get() { return (this as? JsonPrimitive)?.takeIf { it.isString }?.content }


internal val JsonElement?.asNumber: Long?
    get() { return (this as? JsonPrimitive)?.content?.toLongOrNull() }

