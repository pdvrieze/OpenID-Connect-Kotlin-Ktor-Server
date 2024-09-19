package io.github.pdvrieze.openid.web.tags

import io.github.pdvrieze.openid.web.WebContext
import kotlinx.html.HEAD
import kotlinx.html.HtmlTagMarker
import kotlinx.html.base
import kotlinx.html.link
import kotlinx.html.meta
import kotlinx.html.script
import kotlinx.html.styleLink
import kotlinx.html.title
import kotlinx.html.unsafe

@HtmlTagMarker
fun HEAD.header(context: WebContext, title: String?) {
    base { href=context.config.issuer }

    meta(charset = "utf-8")
    title("${context.config.topbarTitle}${title?.let{ " – $it"} ?: ""}")

    meta(name="viewport", content="width=device-width, initial-scale=1.0")
    meta(name="description", content="")
    meta(name="author", content="")
    meta(name="referrer", content="strict-origin-when-cross-origin")

    styleLink(url="resources/bootstrap2/css/bootstrap.css")
    styleLink(url="resources/css/bootstrap-sheet.css")
    styleLink(url="resources/css/mitreid-connect.css")
    styleLink(url="resources/css/mitreid-connect-local.css")
    styleLink(url="resources/bootstrap2/css/bootstrap-responsive.css")
    styleLink(url="resources/css/mitreid-connect-responsive.css")
    styleLink(url="resources/css/mitreid-connect-responsive-local.css")

    // Don't incorporate IE6-8 html5 shims

    link(rel="shortcut icon", href = "resources/images/mitreid-connect.ico")

    script(type="text/javascript", src="resources/js/lib/jquery.js") {}
    script(type="text/javascript", src="resources/js/lib/moment-with-locales.js") {}
    script(type="text/javascript", src="resources/js/lib/i18next.js") {}
    val config = context.config
    script(type="text/javascript") {
        unsafe {
            raw("""
        |${'$'}.i18n.init({
        |    fallbackLng: "en",
        |    lng: "${config.locale}",
        |    resGetPath: "resources/js/locale/__lng__/__ns__.json",
        |    ns: {
        |        namespaces: ${config.languageNamespacesString},
        |        defaultNs: '${config.defaultLanguageNamespace}'
        |    },
        |    fallbackNS: ${config.languageNamespacesString}
        |});
        |moment.locale("${config.locale}");
        |// safely set the title of the application
        |function setPageTitle(title) {
        |    document.title = "${config.topbarTitle} - " + title;
        |}
        |
        |// get the info of the current user, if available (null otherwise)
        |function getUserInfo() {
        |    return ${context.userInfoJson};
        |}
        |
        |// get the authorities of the current user, if available (null otherwise)
        |function getUserAuthorities() {
        |    return ${context.userAuthorities};
        |}
        |
        |// is the current user an admin?
        |// NOTE: this is just for  
        |function isAdmin() {
        |    var auth = getUserAuthorities();
        |    if (auth && _.contains(auth, "ROLE_ADMIN")) {
        |        return true;
        |    } else {
        |        return false;
        |    }
        |}
        |
        |var heartMode = ${config.isHeartMode};
            """.trimMargin())
        }
    }

}
