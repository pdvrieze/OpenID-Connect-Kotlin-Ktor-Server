package io.github.pdvrieze.auth.ktor

import io.github.pdvrieze.auth.UserService
import org.mitre.web.util.OpenIdContext

interface KtorOpenIdContext : OpenIdContext {
    val userService: UserService
}
