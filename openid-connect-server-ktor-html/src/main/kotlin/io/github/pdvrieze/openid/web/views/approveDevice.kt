import io.github.pdvrieze.openid.web.WebContext
import io.github.pdvrieze.openid.web.tags.formattedPage
import io.github.pdvrieze.openid.web.tags.topBar
import kotlinx.html.*
import org.mitre.oauth2.exception.OAuth2Exception
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.OAuthClientDetails.SubjectType
import org.mitre.oauth2.model.SystemScope


fun <T, C : TagConsumer<T>> C.approveDevice(
    context: WebContext,
    client: OAuthClientDetails,
    scopes: Set<SystemScope>,
    claims:  Map<String?, Map<String, String>>,
    isApproved: Boolean,
    exception: OAuth2Exception?,
    count:Int = 0,
    gras: Boolean = false,
    contacts: String? = null,
): T {
    val title = context.intl.messageText("approve.title")
    val clientId = client.clientId
    val clientName = client.clientName?.takeUnless { it.isBlank() }
    val clientDescription = client.clientDescription
    val clientUri = client.clientUri
    val policyUri = client.policyUri
    val tosUri = client.tosUri
    val _csrf = context.csrf

    return formattedPage(context, title) {
        topBar(context, "Approve")

        with(context.intl) {


            div(classes="container main") {

                if (exception != null /*&& exception !is UnapprovedClientAuthenticationException*/) {
                    div(classes="alert-message error") {
                        a(href="#", classes="close") {; +Entities.times;}

                        p {
                            strong {message("approve.error.not_granted")}
                            +"(${exception.message})"

                        }
                    }
                }

                // <c:remove scope="session" var="SPRING_SECURITY_LAST_EXCEPTION" />

                div(classes="well", ) {
                    style="text-align: center"
                    h1 {message("approve.required_for",  )
                        +Entities.nbsp
                        +(clientName ?: clientId!!)
                    }

                    form(action = context.issuerUrl("device/approve"), method = FormMethod.post) {
                        name="confirmationForm"

                        div(classes="row") {
                            div(classes="span5 offset1 well-small", ) {
                                style="text-align: left"
                                if (client.isDynamicallyRegistered) {
                                    when {
                                        gras  -> {
                                            comment("client is \"generally recognized as safe, display a more muted block")
                                            div {
                                                p(classes = "alert alert-info") {
                                                    i(classes = "icon-globe") {}

                                                    message("approve.dynamically_registered",)

                                                }
                                            }
                                        }
                                        else -> {
                                            comment("client is dynamically registered")
                                            div(classes="alert alert-block ${if(count==0) "alert-error" else "alert-warn"} ") {
                                                h4 {
                                                    i(classes="icon-globe")
                                                    message("approve.caution.title")
                                                    +":"
                                                }

                                                p { message("approve.dynamically_registered",  client.createdAt) }
                                                p {
                                                    when (count) {
                                                        0 -> message("approve.caution.message.none",  count)
                                                        1 -> message("approve.caution.message.singular",  count)
                                                        else -> message("approve.caution.message.plural", count)
                                                    }
                                                }
                                            }
                                        }
                                    }
                                } // end if client dynamically registered

                                if ( (! client.logoUri.isNullOrBlank())) {
                                    ul(classes="thumbnails") {
                                        li(classes="span5") {
                                            a(classes = "thumbnail") {
                                                attributes["data-toggle"] = "modal"
                                                attributes["data-target"] = "#logoModal"
                                                img(src = "api/clients/${client.id}/logo")
                                            }
                                        }
                                    }
                                    comment("Modal")
                                    div(classes="modal hide fade") {
                                        id="logoModal"
                                        tabIndex="-1"
                                        role="dialog"
                                        attributes["aria-labelledby"]="logoModalLabel"
                                        attributes["aria-hidden"]="true"
                                        div(classes="modal-header") {
                                            button(type=ButtonType.button, classes="close",) {
                                                attributes["data-dismiss"]="modal"
                                                attributes["aria-hidden"]="true"
                                                +Entities.times;
                                            }
                                            h3 {
                                                id="logoModalLabel"
                                                +(clientName ?: clientId!!)
                                            }
                                        }
                                        div(classes="modal-body") {
                                            img(src="api/clients/${ client.id }/logo" )
                                            if (! clientUri.isNullOrBlank()) {
                                                a(href= clientUri) { +clientUri }
                                            }
                                        }
                                        div(classes="modal-footer") {
                                            button(classes="btn",) {
                                                attributes["data-dismiss"]="modal"
                                                attributes["aria-hidden"]="true"
                                                +"Close"
                                            }
                                        }
                                    }
                                }
                                if (clientDescription.isNotBlank() || ! clientUri.isNullOrBlank() ||
                                    ! policyUri.isNullOrBlank() || ! tosUri.isNullOrBlank() || ! contacts.isNullOrBlank()
                                ) {
                                    div(classes="muted moreInformationContainer") {
                                        +clientDescription
                                        if (( (! clientUri.isNullOrBlank())) || ( (! policyUri.isNullOrBlank())) || ( (! tosUri.isNullOrBlank()))  || ( (! contacts.isNullOrBlank()))) {
                                            div {
                                                id="toggleMoreInformation"
                                                style="cursor: pointer;"
                                                small {
                                                    i(classes="icon-chevron-right")
                                                    message("approve.more_information")
                                                }
                                            }
                                            div(classes="hide") {
                                                id="moreInformation"
                                                ul {
                                                    if ( (! clientUri.isNullOrBlank())) {
                                                        li {
                                                            message("approve.home_page")
                                                            +": "
                                                            a(href = "$clientUri") { +clientUri }
                                                        }
                                                    }
                                                    if ( (! policyUri.isNullOrBlank())) {
                                                        li {
                                                            message("Policy")
                                                            +": "
                                                            a(href = "$policyUri") { +policyUri }
                                                        }
                                                    }
                                                    if ( (! tosUri.isNullOrBlank())) {
                                                        li {
                                                            message("approve.terms",  )
                                                            +": "
                                                            a(href="$tosUri") { +tosUri }
                                                        }
                                                    }
                                                    if (( (! contacts.isNullOrBlank()))) {
                                                        li {message("approve.contacts"); +": $contacts" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                if (client.subjectType == SubjectType.PAIRWISE) {
                                    div(classes="alert alert-success") {
                                        message("approve.pairwise",  )
                                    }
                                }

                            } // span5
                            div(classes="span4") {
                                fieldSet(classes="well") {
                                    style="text-align: left"
                                    legend {
                                        style="margin-bottom: 0"
                                        message("approve.access_to")
                                        +":"
                                    }

                                    if (scopes.isNullOrEmpty()) {
                                        div(classes = "alert alert-block alert-error") {
                                            h4 {
                                                i(classes = "icon-info-sign") {}
                                                message("approve.warning")
                                                +":"
                                            }
                                            p { message("approve.no_scopes") }
                                        }
                                    } else {
                                        ul {
                                            for (scope in scopes) {
                                                li {
                                                    if ((!scope.icon.isNullOrBlank())) i(classes = "icon-${scope.icon}")
                                                    +(scope.description?.takeUnless { it.isBlank() } ?: scope.value!!)

                                                    val scopeClaims = claims[scope.value]

                                                    if (!scopeClaims.isNullOrEmpty()) {
                                                        span(classes = "claim-tooltip") {
                                                            attributes["data-toggle"] = "popover"
                                                            attributes["data-html"] = "true"
                                                            attributes["data-placement"] = "right"
                                                            attributes["data-trigger"] = "hover"
                                                            attributes["data-title"] = "These values will be sent:"
                                                            attributes["data-content"] = scopeClaims.entries.joinToString(
                                                                separator = "",
                                                                prefix = "<div style='text-align: left;'><ul>",
                                                                postfix = "</ul></div>",
                                                            ) { (k, v) ->
                                                                "<li><b>$k</b>: $v</li>"
                                                            }

                                                            i(classes = "icon-question-sign") {}
                                                        }
                                                    }
                                                }
                                            } // for scope
                                        } //end ul
                                    }
                                } // end fieldset
                            } // div span4

                        } // div row



                        div(classes="row") {
                            h3 {
                                message("approve.do_authorize")
                                +(clientName ?: clientId!!)
                                +"?"
                            }
                            input(InputType.hidden, name = "user_oauth_approval") {
                                id = "user_oauth_approval"
                                value = "true"
                            }
                            input(InputType.hidden, name = "user_code") {
                                value = "\${ dc.userCode }" // TODO dc.userCode is not defined
                            }
                            input(InputType.hidden, name = _csrf.parameterName) {
                                value = _csrf.token
                            }
                            input(InputType.submit, name = "authorize", classes = "btn btn-success btn-large") {
                                onClick = "\$('#user_oauth_approval').attr('value',true)"
                                value = messageText("approve.label.authorize")
                            }
                            +Entities.nbsp
                            input(name = "deny", type = InputType.submit, classes = "btn btn-secondary btn-large") {
                                onClick = "\$('#user_oauth_approval').attr('value',false)"
                                value = messageText("approve.label.deny")
                            }
                        }

                    }

                }
            }
            script(type="text/javascript") {
                unsafe {
                    raw(
                        """|<!--
                        |
                        |${'$'}(document).ready(function() {
                        |        ${'$'}('.claim-tooltip').popover();
                        |        ${'$'}('.claim-tooltip').on('click', function(e) {
                        |            e.preventDefault();
                        |            ${'$'}(this).popover('show');
                        |        });
                        |
                        |        ${'$'}(document).on('click', '#toggleMoreInformation', function(event) {
                        |            event.preventDefault();
                        |            if (${'$'}('#moreInformation').is(':visible')) {
                        |                // hide it
                        |                ${'$'}('.moreInformationContainer', this.el).removeClass('alert').removeClass('alert-info').addClass('muted');
                        |                ${'$'}('#moreInformation').hide('fast');
                        |                ${'$'}('#toggleMoreInformation i').attr('class', 'icon-chevron-right');
                        |            } else {
                        |                // show it
                        |                ${'$'}('.moreInformationContainer', this.el).addClass('alert').addClass('alert-info').removeClass('muted');
                        |                ${'$'}('#moreInformation').show('fast');
                        |                ${'$'}('#toggleMoreInformation i').attr('class', 'icon-chevron-down');
                        |            }
                        |        });
                        |        
                        |        var creationDate = "<c:out value="${client.createdAt}" />";
                        |        var displayCreationDate = ${'$'}.t('approve.dynamically-registered-unkown');
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
                        |        ${'$'}('#registrationTime').html(displayCreationDate);
                        |        ${'$'}('#registrationTime').attr('title', hoverCreationDate);
                        |
                        |        
                        |        
                        |});
                        |
                        |//-->""".trimMargin()
                    )
                }
            }
        }
    }
}

