package io.github.pdvrieze.openid.web.views

import io.github.pdvrieze.openid.web.WebContext
import io.github.pdvrieze.openid.web.style.styleAttr
import io.github.pdvrieze.openid.web.tags.a_data
import io.github.pdvrieze.openid.web.tags.formattedPage
import io.github.pdvrieze.openid.web.tags.topBar
import kotlinx.css.TextAlign
import kotlinx.css.textAlign
import kotlinx.html.*
import org.mitre.oauth2.exception.OAuth2Exception
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.OAuthClientDetails.SubjectType
import org.mitre.oauth2.model.SystemScope
import java.net.URI

// TODO limit exception to unnapproved authentication
/**
 * @param client The client this refers to
 * @param isGras Is "Generally Recognised As Safe"
 * @param authenticationException An exception to display the message for
 */
fun <T, C : TagConsumer<T>> C.approve(
    context: WebContext,
    authRequest: Nothing?,
    client: OAuthClientDetails,
    redirectUri: URI,
    scopes: Set<SystemScope>,
    claims:  Map<String?, Map<String, String>>,
    count: Int,
    contacts: String? = null,
    isGras: Boolean,
    consent: Boolean = true,
    authenticationException: OAuth2Exception? = null,
): T {
    val title = context.intl.messageText("approve.title")
    val pageName = "Approve"
    val clientUri = client.clientUri
    val _csrf = context.csrf
    return formattedPage(context, title) {
        with(context.intl) {
            topBar(context, pageName)
            div("container main") {
                if (authenticationException != null /*&& authenticationException !is UnapprovedClientAuthenticationException*/) {
                    div("alert-message error") {
                        a(href = "#", classes = "close") { +Entities.times }
                        p {
                            strong { message("approve.error.not_granted") }
                            +"( ${authenticationException.message} )"
                        }
                    }

                }

                // remove LAST_EXCEPTION from session

                div("well") {
                    styleAttr { textAlign = TextAlign.center }
                    h1 {
                        message("approve.required_for")
                        +Entities.nbsp
                        em { +(client.clientName ?: client.clientId!!) }
                    }
                    form(action=context.issuerUrl("authorize"), method=FormMethod.post) {
                        name="confirmationForm"


                        div("row") {
                            div("span5 offset1 well-small") {
                                styleAttr { textAlign = TextAlign.left }
                                if (client.isDynamicallyRegistered) {
                                    if (isGras) {
                                        comment("client is \"generally recognized as safe\", display a more muted block")
                                        div {
                                            p("alert alert-info") {
                                                i("icon-globe")
                                                message("approve.dynamically_registered")
                                            }
                                        }
                                    } else {
                                        comment("client is dynamically registered")

                                        div("alert alert-block ${if (count == 0) "alert-error" else "alert-warn"}") {
                                            h4() {
                                                i("icon-globe") {}
                                                message("approve.caution.title")
                                            }

                                            p() { message("approve.dynamically_registered", client.createdAt) }
                                            p() {
                                                when (count) {
                                                    0 -> message("approve.caution.message.none", count)
                                                    1 -> message("approve.caution.message.singular", count)
                                                    else -> message("approve.caution.message.plural", count)
                                                }
                                            }
                                        }
                                    }
                                } // if dynamically registered


                                if (!client.logoUri.isNullOrBlank()) {
                                    ul(classes = "thumbnails") {
                                        li(classes = "span5") {
                                            a_data(classes = "thumbnail", dataToggle = "modal", dataTarget = "#logoModal") {
                                                img(src = "api/clients/${client.id}/logo")
                                            }
                                        }
                                    }
                                    comment("Modal")
                                    div(classes = "modal hide fade") {
                                        id = "logoModal"
                                        tabIndex = "-1"
                                        role = "dialog"
                                        attributes["aria-labelledby"] = "logoModalLabel"
                                        attributes["aria-hidden"] = "true"
                                        div(classes = "modal-header") {
                                            button(type = ButtonType.button, classes = "close") {
                                                attributes["data-dismiss"] = "modal"
                                                attributes["aria-hidden"] = "true"
                                                +Entities.times
                                            }
                                        }
                                        h3 {
                                            id = "logoModalLabel"
                                            +(client.clientName ?: client.clientId!!)
                                        }
                                    }
                                    div(classes = "modal-body") {
                                        img(src = "api/clients/${client.id}/logo")
                                        if ((!clientUri.isNullOrBlank())) {
                                            a(href = "${clientUri}") { +clientUri!! }
                                        }
                                    }
                                    div(classes = "modal-footer") {
                                        button(classes = "btn",) {
                                            attributes["data-dismiss"] = "modal"
                                            attributes["aria-hidden"] = "true"
                                            +"Close"
                                        }
                                    }
                                } // end if has logoUri

                                if (((!client.clientDescription.isNullOrBlank())) || ((!clientUri.isNullOrBlank())) || ((!client.policyUri.isNullOrBlank())) || ((!client.tosUri.isNullOrBlank())) || ((!contacts.isNullOrBlank()))) {
                                    div(classes = "muted moreInformationContainer") {
                                        +client.clientDescription
                                        if (((!clientUri.isNullOrBlank())) || ((!client.policyUri.isNullOrBlank())) || ((!client.tosUri.isNullOrBlank())) || ((!contacts.isNullOrBlank()))) {
                                            div() {
                                                id = "toggleMoreInformation"
                                                style = "cursor: pointer;"
                                                small() {
                                                    i(classes = "icon-chevron-right")
                                                    message("approve.more_information",)
                                                }
                                            }
                                            div(classes = "hide") {
                                                id = "moreInformation"
                                                ul() {
                                                    if ((!clientUri.isNullOrBlank())) {
                                                        li() {
                                                            message("approve.home_page",)
                                                            +": "
                                                            a("$clientUri") { +clientUri }
                                                        }
                                                    }
                                                    if ((!client.policyUri.isNullOrBlank())) {
                                                        li() {
                                                            message("Policy",)
                                                            +": "
                                                            a(href = "${client.policyUri}") { +(client.policyUri!!) }
                                                        }
                                                    }
                                                    if ((!client.tosUri.isNullOrBlank())) {
                                                        li() {
                                                            message("approve.terms",)
                                                            +": "
                                                            a(href = "${client.tosUri}") { +client.tosUri!! }
                                                        }
                                                    }
                                                    if (((!contacts.isNullOrBlank()))) {
                                                        li() { message("approve.contacts"); +": $contacts" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                } // client description
                                div() { // redirect block
                                    when {
                                        client.redirectUris.isNullOrEmpty() ->
                                            div(classes = "alert alert-block alert-error") {
                                                h4() {
                                                    i(classes = "icon-info-sign") {}
                                                    message("approve.warning")
                                                    +":"
                                                }
                                                message("approve.no_redirect_uri",)
                                                message("approve.redirect_uri", redirectUri)
                                            }

                                        else -> message("approve.redirect_uri", redirectUri)
                                    }
                                } // end redirect block

                                if (client.subjectType == SubjectType.PAIRWISE) {
                                    div(classes = "alert alert-success") {
                                        message("approve.pairwise",)
                                    }
                                }
                            }// div class="span5"
                            div(classes = "span4") {
                                fieldSet(classes = "well") {
                                    style = "text-align: left"
                                    legend() {
                                        style = "margin-bottom: 0;"
                                        message("approve.access_to")
                                        +": "
                                    }

                                    if (client.scope.isNullOrEmpty()) {
                                        div(classes = "alert alert-block alert-error") {
                                            h4 {
                                                i(classes = "icon-info-sign")
                                                message("approve.warning",)
                                                +":"
                                            }
                                            p { message("approve.no_scopes") }
                                        }
                                    }

                                    for (scope in scopes) {

                                        label(classes = "checkbox") {
                                            htmlFor = "scope_${scope.value}"
                                            input(type = InputType.checkBox,) {
                                                id = "scope_${scope.value}"
                                                checked = true
                                                value = scope.value ?: ""
                                                name = "scope_${scope.value}"
                                                if ((!scope.icon.isNullOrBlank())) {
                                                    i(classes = "icon-${scope.icon}") {}
                                                }
                                                when {
                                                    (!scope.description.isNullOrBlank()) ->
                                                        +scope.description!!

                                                    else -> +scope.value!!
                                                }

                                                val scopeClaims = claims[scope.value]
                                                if ((!scopeClaims.isNullOrEmpty())) {
                                                    span(classes = "claim-tooltip") {
                                                        attributes["data-toggle"] = "popover"
                                                        attributes["data-html"] = "true"
                                                        attributes["data-placement"] = "right"
                                                        attributes["data-trigger"] = "hover"
                                                        attributes["data-title"] = "These values will be sent:"

                                                        attributes["data-content"] = scopeClaims.entries.joinToString(
                                                            separator = "",
                                                            prefix = "<div style='text-align: left'><ul>",
                                                            postfix = "</ul></div>",
                                                        ) { (k, v) ->
                                                            "<li><b>$k</b>: $v</li>"
                                                        }
                                                    }
                                                    i(classes = "icon-question-sign")
                                                }
                                            }

                                        }

                                    }

                                } // fieldSet well

                                fieldSet(classes = "well") {
                                    style = "text-align: left"
                                    legend {
                                        style = "margin-bottom: 0;"
                                        message("approve.remember.title")
                                        +":"
                                    }
                                    label(classes = "radio") {
                                        htmlFor = "remember-forever"
                                        input(type = InputType.radio) {
                                            checked = !consent
                                            id = "remember-forever"
                                            name = "remember"
                                            value = "until-revoked"
                                            message("approve.remember.until_revoke",)
                                        }
                                    }
                                    label(classes = "radio") {
                                        htmlFor = "remember-hour"
                                        input(type = InputType.radio) {
                                            id = "remember-hour"
                                            name = "remember"
                                            value = "one-hour"
                                            message("approve.remember.one_hour",)
                                        }
                                    }
                                    label(classes = "radio") {
                                        htmlFor = "remember-not"
                                        input(type = InputType.radio) {
                                            id = "remember-not"
                                            checked = consent
                                            name = "remember"
                                            value = "none"
                                            message("approve.remember.next_time",)
                                        }
                                    }
                                } // fieldset

                            } // div span4
                        } // div row
                        
                        div(classes="row") {
                            h3() {
                                message("approve.do_authorize")
                                +"\"${client.clientName ?: client.clientId}\"?"
                            }
                            val authorize_label=messageText("approve.label.authorize")
                            val deny_label = message("approve.label.deny")
                            input(type=InputType.hidden, name="user_oauth_approval") {
                                id="user_oauth_approval"
                                value="true"
                            }
                            input(type=InputType.hidden, name="${_csrf.parameterName}") { value="${_csrf.token}" }
                            input(name="authorize", type=InputType.submit, classes="btn btn-success btn-large") {
                                onClick="\$('#user_oauth_approval').attr('value',true)"
                        
                                value="$authorize_label"
                            }
                            +Entities.nbsp
                            input(name="deny", type=InputType.submit, classes="btn btn-secondary btn-large") {
                                value="${deny_label}"
                                onClick="$('#user_oauth_approval').attr('value',false)"
                            }   
                        } // row

                    }// form
                } // div well   

            } //div container main

            script(type="text/javascript") {
                unsafe { 
                    raw("""
                    |<!--
                    |$(document).ready(function() {
                    |        $('.claim-tooltip').popover();
                    |        $('.claim-tooltip').on('click', function(e) {
                    |            e.preventDefault();
                    |            $(this).popover('show');
                    |        });
                    |
                    |        $(document).on('click', '#toggleMoreInformation', function(event) {
                    |            event.preventDefault();
                    |            if ($('#moreInformation').is(':visible')) {
                    |                // hide it
                    |                $('.moreInformationContainer', this.el).removeClass('alert').removeClass('alert-info').addClass('muted');
                    |                $('#moreInformation').hide('fast');
                    |                $('#toggleMoreInformation i').attr('class', 'icon-chevron-right');
                    |            } else {
                    |                // show it
                    |                $('.moreInformationContainer', this.el).addClass('alert').addClass('alert-info').removeClass('muted');
                    |                $('#moreInformation').show('fast');
                    |                $('#toggleMoreInformation i').attr('class', 'icon-chevron-down');
                    |            }
                    |        });
                    |        
                    |        var creationDate = "<c:out value="${ client.createdAt }" />";
                    |        var displayCreationDate = $.t('approve.dynamically-registered-unkown');
                    |        var hoverCreationDate = "";
                    |        if (creationDate != null && moment(creationDate).isValid()) {
                    |            creationDate = moment(creationDate);
                    |            if (moment().diff(creationDate, 'months') < 6) {
                    |                displayCreationDate = creationDate.fromNow();
                    |            } else {
                    |                displayCreationDate = "on " + creationDate.format("LL");
                    |            }
                    |            hoverCreationDate = creationDate.format("LLL");
                    |        }
                    |        
                    |        $('#registrationTime').html(displayCreationDate);
                    |        $('#registrationTime').attr('title', hoverCreationDate);
                    |
                    |        
                    |        
                    |});
                    |
                    |//-->
                    """.trimMargin())
                }
            }
        }
    }
}
