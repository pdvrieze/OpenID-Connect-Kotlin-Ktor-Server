package org.mitre.oauth2.service

interface IBlacklistAwareRedirectResolver: RedirectResolver {
    var isStrictMatch: Boolean
}
