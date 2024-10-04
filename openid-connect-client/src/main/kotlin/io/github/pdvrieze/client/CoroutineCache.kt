package io.github.pdvrieze.client

import com.google.common.cache.CacheBuilder
import com.google.common.cache.CacheLoader
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.future.await
import kotlinx.coroutines.future.future
import java.util.concurrent.CompletableFuture
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.EmptyCoroutineContext

class CoroutineCache<K, V>(
    loaderFunction: suspend (K) -> V,
    configure: CacheBuilder<*, *>.() -> Unit = {}
) {

    private class CoroutineLoader<K, V>(private val loaderFunction: suspend (K) -> V) : CacheLoader<K, CompletableFuture<V>>(),
                                                                                CoroutineScope {
        override val coroutineContext: CoroutineContext
            get() = EmptyCoroutineContext

        override fun load(key: K): CompletableFuture<V> {
            return future { loaderFunction(key) }
        }
    }


    private val cache = CacheBuilder.newBuilder().apply(configure).build(CoroutineLoader(loaderFunction))

    suspend fun load(key: K): V {
        return cache[key].await()
    }

}
