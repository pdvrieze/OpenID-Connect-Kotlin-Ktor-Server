/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.mitre.openid.connect.view

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import org.mitre.jwt.signer.service.ClientKeyCacheService
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.jwt.signer.service.impl.SymmetricKeyJWTValidatorCacheService
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.util.getLogger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.stereotype.Component
import java.io.IOException
import java.io.Writer
import java.text.ParseException
import java.util.*
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * @author jricher
 */
@Component(UserInfoJWTView.VIEWNAME)
class UserInfoJWTView : UserInfoView() {
    @Autowired
    private lateinit var jwtService: JWTSigningAndValidationService

    @Autowired
    private lateinit var config: ConfigurationPropertiesBean

    @Autowired
    private lateinit var encrypters: ClientKeyCacheService

    @Autowired
    private lateinit var symmetricCacheService: SymmetricKeyJWTValidatorCacheService

    override fun writeOut(
        json: JsonObject,
        model: Map<String, Any>,
        request: HttpServletRequest?,
        response: HttpServletResponse
    ) {
        try {
            val client = model[CLIENT] as ClientDetailsEntity

            // use the parser to import the user claims into the object
            val encodedJson = Json.encodeToString(json)

            response.contentType = JOSE_MEDIA_TYPE_VALUE

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

                val encrypter = runBlocking { encrypters.getEncrypter(client) }

                if (encrypter != null) {
                    val encrypted =
                        EncryptedJWT(JWEHeader(client.userInfoEncryptedResponseAlg, client.userInfoEncryptedResponseEnc), claims)

                    encrypter.encryptJwt(encrypted)


                    val out: Writer = response.writer
                    out.write(encrypted.serialize())
                } else {
                    Companion.logger.error("Couldn't find encrypter for client: " + client.clientId)
                }
            } else {
                var signingAlg = jwtService.defaultSigningAlgorithm // default to the server's preference
                val userInfoSignedResponseAlg = client.userInfoSignedResponseAlg?.let { signingAlg = it }

                val header = JWSHeader.Builder(signingAlg)
                    .keyID(jwtService.defaultSignerKeyId)
                    .build()

                val signed = SignedJWT(header, claims)

                if (signingAlg in JWSAlgorithm.Family.HMAC_SHA) {
                    // sign it with the client's secret

                    val signer = symmetricCacheService.getSymmetricValidator(client)
                    signer!!.signJwt(signed)
                } else {
                    // sign it with the server's key
                    jwtService.signJwt(signed)
                }

                val out: Writer = response.writer
                out.write(signed.serialize())
            }
        } catch (e: IOException) {
            Companion.logger.error("IO Exception in UserInfoJwtView", e)
        } catch (e: ParseException) {
            // TODO Auto-generated catch block
            e.printStackTrace()
        }
    }

    companion object {
        const val CLIENT: String = "client"

        /**
         * Logger for this class
         */
        private val logger = getLogger<UserInfoJWTView>()

        const val VIEWNAME: String = "userInfoJwtView"

        const val JOSE_MEDIA_TYPE_VALUE: String = "application/jwt"
        val JOSE_MEDIA_TYPE: MediaType = MediaType("application", "jwt")
    }
}
