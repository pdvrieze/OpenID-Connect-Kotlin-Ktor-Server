package io.github.pdvrieze.openid.web.tags

import io.github.pdvrieze.openid.web.WebContext
import kotlinx.html.BODY
import kotlinx.html.HtmlTagMarker
import kotlinx.html.div
import kotlinx.html.id
import kotlinx.html.p
import kotlinx.html.script
import kotlinx.html.unsafe

@HtmlTagMarker
fun BODY.footer(context: WebContext, js: Boolean = false) {
    comment("end #wrap")

    div{
        id="footer"
        div("container") {
            p("muted credit") { copyright(context) }
        }
    }

    comment("Javascript -- footer for speed")
    script("text/javascript", "resources/bootstrap2/js/bootstrap.js") {}
    script("text/javascript", "resources/js/lib/underscore.js") {}
    script("text/javascript", "resources/js/lib/backbone.js") {}
    script("text/javascript", "resources/js/lib/purl.js") {}
    script("text/javascript", "resources/js/lib/bootstrapx-clickover.js") {}
    script("text/javascript", "resources/js/lib/bootstrap-sheet.js") {}
    script("text/javascript", "resources/js/lib/bootpag.js") {}
    script("text/javascript", "resources/js/lib/retina.js") {}

    if(js) {
        script("text/javascript") {
            unsafe {
                raw("""
                |// set up a global variable for UI components to hang extensions off of
                |
                |var ui = {
                |  templates: ["resources/template/admin.html"], // template files to load for UI
                |  routes: [], // routes to add to the UI {path: URI to map to, name: unique name for internal use, callback: function to call when route is activated}
                |  init: [] // functions to call after initialization is complete
                |};
                """.trimMargin().prependIndent("    "))
            }
        }
        for(file in context.ui.jsFiles) {
            script("text/javascript", file) {}
        }
        script("text/javascript", "resources/js/admin.js") {}
    }
    div("hide") { id="templates" }
}
