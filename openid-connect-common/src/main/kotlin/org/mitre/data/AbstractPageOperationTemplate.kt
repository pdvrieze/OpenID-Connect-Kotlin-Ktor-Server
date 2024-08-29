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
package org.mitre.data

import org.mitre.util.getLogger

/**
 * Abstract class for performing an operation on a potentially large
 * number of items by paging through the items in discreet chunks.
 *
 * @param T  the type parameter
 * @author Colm Smyth.
 *
 * @property maxPages int specifying the maximum number of pages which should be fetched before execution should
 *                    terminate.
 * @property maxTime long specifying the maximum execution time in milliseconds
 * @property operationName String that is used for logging in final tallies
 */
abstract class AbstractPageOperationTemplate<T>(
    var operationName: String,
    var maxPages: Int = DEFAULT_MAX_PAGES,
    var maxTime: Long = DEFAULT_MAX_TIME_MILLIS,
) {
    /**
     * boolean specifying whether or not Exceptions
     * incurred performing the operation should be
     * swallowed during execution default true.
     */
    var isSwallowExceptions: Boolean = true

    @Deprecated("Compatibility with original implementation", ReplaceWith("AbstractPageOperationTemplate<T>(operationName, maxPages, maxTime)"))
    constructor(maxPages: Int, maxTime: Long, operationName: String): this (operationName, maxPages, maxTime)

    /**
     * Execute the operation on each member of a page of results
     * retrieved through the fetch method. the method will execute
     * until either the maxPages or maxTime limit is reached or until
     * the fetch method returns no more results. Exceptions thrown
     * performing the operation on the item will be swallowed if the
     * swallowException (default true) field is set true.
     */
    fun execute() {
        logger.debug("[$operationName] Starting execution of paged operation. maximum time: $maxTime, maximum pages: $maxPages")

        val startTime = System.currentTimeMillis()
        var executionTime: Long = 0
        var i = 0

        var exceptionsSwallowedCount = 0
        var operationsCompleted = 0
        val exceptionsSwallowedClasses: MutableSet<String> = HashSet()


        while (i < maxPages && executionTime < maxTime) {
            val page = fetchPage()
            if (page == null || page.size == 0) {
                break
            }

            for (item in page) {
                try {
                    doOperation(item)
                    operationsCompleted++
                } catch (e: Exception) {
                    if (isSwallowExceptions) {
                        exceptionsSwallowedCount++
                        exceptionsSwallowedClasses.add(e.javaClass.name)
                        logger.debug("Swallowing exception " + e.message, e)
                    } else {
                        logger.debug("Rethrowing exception " + e.message, e)
                        throw e
                    }
                }
            }

            i++
            executionTime = System.currentTimeMillis() - startTime
        }

        finalReport(operationsCompleted, exceptionsSwallowedCount, exceptionsSwallowedClasses)
    }


    /**
     * method responsible for fetching
     * a page of items.
     *
     * @return the collection of items
     */
    abstract fun fetchPage(): Collection<T>?

    /**
     * method responsible for performing desired
     * operation on a fetched page item.
     *
     * @param item the item
     */
    protected abstract fun doOperation(item: T)

    /**
     * Method responsible for final report of progress.
     */
    protected fun finalReport(
        operationsCompleted: Int,
        exceptionsSwallowedCount: Int,
        exceptionsSwallowedClasses: Set<String>
    ) {
        if (operationsCompleted > 0 || exceptionsSwallowedCount > 0) {
            logger.info("[$operationName] Paged operation run: completed $operationsCompleted; swallowed $exceptionsSwallowedCount exceptions")
        }
        for (className in exceptionsSwallowedClasses) {
            logger.warn("[$operationName] Paged operation swallowed at least one exception of type $className")
        }
    }


    companion object {
        private val logger = getLogger<AbstractPageOperationTemplate<*>>()

        private const val DEFAULT_MAX_PAGES = 1000
        private const val DEFAULT_MAX_TIME_MILLIS = 600000L //10 Minutes
    }
}
