package org.mitre.oauth2.service

interface BlacklistAwareRedirectResolver: RedirectResolver {
    var isStrictMatch: Boolean
}
