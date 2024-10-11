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
package org.mitre.openid.connect.service.impl.ktor

import io.github.pdvrieze.oidc.util.CoroutineCache
import io.github.pdvrieze.oidc.util.expireAfterAccess
import io.ktor.client.*
import io.ktor.client.engine.java.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.openid.connect.model.CachedImage
import org.mitre.openid.connect.service.ClientLogoLoadingService
import java.util.concurrent.ExecutionException
import kotlin.time.Duration.Companion.days

/**
 * @author jricher
 */
class KtorInMemoryClientLogoLoadingService(
    private val httpClient: HttpClient = HttpClient(Java) {},
) : ClientLogoLoadingService {
    private val cache = CoroutineCache(::fetchLogo) {
        maximumSize(10)
        expireAfterAccess(14.days)
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.service.ClientLogoLoadingService#getLogo(org.mitre.oauth2.model.ClientDetailsEntity)
	 */
    override suspend fun getLogo(client: OAuthClientDetails?): CachedImage? {
        return try {
            when (val logoUri = client?.logoUri) {
                null -> null
                else -> cache.load(logoUri)
            }
        } catch (e: ExecutionException) {
            null
        }
    }

    private suspend fun fetchLogo(logoUri: String): CachedImage {
        val response = httpClient.get(logoUri)
        if (!response.status.isSuccess()) {
            throw IllegalArgumentException("Unable to load client image")
        }

        val bytes = response.readBytes()
        return CachedImage(
            data = bytes,
            contentType = response.contentType()!!.contentType,
            length = response.contentLength() ?: bytes.size.toLong(),
        )
    }

}
