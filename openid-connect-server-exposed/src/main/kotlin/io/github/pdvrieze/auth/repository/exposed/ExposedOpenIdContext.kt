package io.github.pdvrieze.auth.repository.exposed

import org.jetbrains.exposed.sql.Database
import org.mitre.web.util.OpenIdContext

interface ExposedOpenIdContext : OpenIdContext {
    val database: Database
}
