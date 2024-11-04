package org.mitre.web.util

import io.ktor.server.sessions.*

interface WebViews

inline fun <reified T : Any> CurrentSession.update(
    updater: (T?) -> T
): T {
    return updater(get<T>()).also { set<T>(it) }
}
