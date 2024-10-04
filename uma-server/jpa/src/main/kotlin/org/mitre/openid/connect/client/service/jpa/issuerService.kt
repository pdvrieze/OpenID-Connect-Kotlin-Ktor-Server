package org.mitre.openid.connect.client.service.jpa

import org.mitre.openid.connect.client.model.IssuerServiceResponse
import org.mitre.openid.connect.client.service.IssuerService
import javax.servlet.http.HttpServletRequest

suspend fun IssuerService.getIssuer(request: HttpServletRequest): IssuerServiceResponse? {
    val p = request.parameterNames
        .asSequence()
        .filterIsInstance<String>()
        .associateWith { k -> request.getParameterValues(k).toList<String>() }
    
    return getIssuer(p, request.requestURI)
}
