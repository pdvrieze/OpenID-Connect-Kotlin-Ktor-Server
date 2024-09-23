package org.mitre.web.util

import io.ktor.server.sessions.*

interface WebViews {

}

public inline fun <reified T : kotlin.Any> CurrentSession.update(
    updater: (T?) -> T
): T {
    return updater(get<T>()).also { set<T>(it) }
}
