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
package org.mitre.openid.connect.service.impl

import com.google.common.cache.CacheBuilder
import com.google.common.cache.CacheLoader
import com.google.common.cache.LoadingCache
import com.google.common.util.concurrent.UncheckedExecutionException
import org.apache.commons.io.IOUtils
import org.apache.http.client.HttpClient
import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.HttpClientBuilder
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.openid.connect.model.CachedImage
import org.mitre.openid.connect.service.ClientLogoLoadingService
import org.springframework.stereotype.Service
import java.io.IOException
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit

/**
 * @author jricher
 */
@Service("inMemoryClientLogoLoadingService")
class InMemoryClientLogoLoadingService(
    httpClient: HttpClient = HttpClientBuilder.create().useSystemProperties().build()
) : ClientLogoLoadingService {
    private val cache: LoadingCache<ClientDetailsEntity, CachedImage> = CacheBuilder.newBuilder()
        .maximumSize(100)
        .expireAfterAccess(14, TimeUnit.DAYS)
        .build(ClientLogoFetcher(httpClient))


    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.service.ClientLogoLoadingService#getLogo(org.mitre.oauth2.model.ClientDetailsEntity)
	 */
    override fun getLogo(client: ClientDetailsEntity?): CachedImage? {
        return try {
            when {
                client == null -> null
                !client.logoUri.isNullOrEmpty() ->
                    cache[client]
                else -> null
            }
        } catch (e: UncheckedExecutionException) {
            null
        } catch (e: ExecutionException) {
            null
        }
    }

    /**
     * @author jricher
     */
    inner class ClientLogoFetcher(
        private val httpClient: HttpClient = HttpClientBuilder.create().useSystemProperties().build()
    ) : CacheLoader<ClientDetailsEntity, CachedImage>() {
        /* (non-Javadoc)
		 * @see com.google.common.cache.CacheLoader#load(java.lang.Object)
		 */
        @Throws(Exception::class)
        override fun load(key: ClientDetailsEntity): CachedImage {
            try {
                val response = httpClient.execute(HttpGet(key.logoUri))

                val entity = response.entity

                val image = CachedImage()

                image.contentType = entity.contentType.value
                image.length = entity.contentLength
                image.data = IOUtils.toByteArray(entity.content)

                return image
            } catch (e: IOException) {
                throw IllegalArgumentException("Unable to load client image.")
            }
        }
    }
}
