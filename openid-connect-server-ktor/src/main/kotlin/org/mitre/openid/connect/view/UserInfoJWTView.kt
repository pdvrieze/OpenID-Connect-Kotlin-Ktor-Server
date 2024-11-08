package org.mitre.openid.connect.view

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.ktor.http.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import org.mitre.jwt.signer.service.ClientKeyCacheService
import org.mitre.jwt.signer.service.impl.SymmetricKeyJWTValidatorCacheService
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.util.getLogger
import org.mitre.util.oidJson
import org.mitre.web.util.openIdContext
import java.util.*

suspend fun RoutingContext.userInfoJWTView(
    encrypters: ClientKeyCacheService,
    symmetricCacheService: SymmetricKeyJWTValidatorCacheService,
    userInfo: JsonObject,
    client: OAuthClientDetails,
    code: HttpStatusCode = HttpStatusCode.OK,
) {
    val openIdContext = openIdContext

    val signService = openIdContext.signService
    val config = openIdContext.config

    val encodedJson = oidJson.encodeToString(userInfo)

    val claims = JWTClaimsSet.Builder(JWTClaimsSet.parse(encodedJson))
        .audience(listOf(client.clientId))
        .issuer(config.issuer)
        .issueTime(Date())
        .jwtID(UUID.randomUUID().toString()) // set a random NONCE in the middle of it
        .build()


    if (client.userInfoEncryptedResponseAlg != null && client.userInfoEncryptedResponseAlg != Algorithm.NONE && client.userInfoEncryptedResponseEnc != null && client.userInfoEncryptedResponseEnc != Algorithm.NONE
        && (!client.jwksUri.isNullOrEmpty() || client.jwks != null)
    ) {
        // encrypt it to the client's key

        val encrypter = encrypters.getEncrypter(client)

        if (encrypter != null) {
            val encrypted =
                EncryptedJWT(JWEHeader(client.userInfoEncryptedResponseAlg, client.userInfoEncryptedResponseEnc), claims)

            encrypter.encryptJwt(encrypted)

            call.respondText(encrypted.serialize(), CT_JWT, code)
        } else {
            UserInfoJWTView.logger.error("Couldn't find encrypter for client: " + client.clientId)
        }
    } else {
        var signingAlg = signService.defaultSigningAlgorithm // default to the server's preference

        // override with the client's preference if available
        client.userInfoSignedResponseAlg?.let { signingAlg = it }

        val header = JWSHeader.Builder(signingAlg)
            .keyID(signService.defaultSignerKeyId)
            .build()

        val signed = SignedJWT(header, claims)

        if (signingAlg == JWSAlgorithm.HS256 || signingAlg == JWSAlgorithm.HS384 || signingAlg == JWSAlgorithm.HS512) {
            // sign it with the client's secret

            val signer = symmetricCacheService.getSymmetricValidator(client)!!
            signer.signJwt(signed)
        } else {
            // sign it with the server's key
            signService.signJwt(signed)
        }

        call.respondText(signed.serialize(), CT_JWT, code)
    }

}

val CT_JWT = ContentType("application", "jwt")

/**
 * @author jricher
 */
object UserInfoJWTView{

    const val CLIENT: String = "client"

    /**
     * Logger for this class
     */
    internal val logger = getLogger<UserInfoJWTView>()

    const val VIEWNAME: String = "userInfoJwtView"
    const val JOSE_MEDIA_TYPE_VALUE: String = "application/jwt"
}
