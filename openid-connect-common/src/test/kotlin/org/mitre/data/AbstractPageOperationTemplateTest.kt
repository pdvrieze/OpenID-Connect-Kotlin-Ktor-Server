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

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.junit.jupiter.api.assertThrows

/**
 * @author Colm Smyth
 */
class AbstractPageOperationTemplateTest {

    @Test
    @Timeout(1000L)
    fun execute_zeropages() {
        val op = CountingPageOperation(0, Long.MAX_VALUE)
        op.execute()

        assertEquals(0L, op.counter)
    }

    @Test
    @Timeout(1000L)
    fun execute_singlepage() {
        val op = CountingPageOperation(1, Long.MAX_VALUE)
        op.execute()

        assertEquals(10L, op.counter)
    }

    @Test
    @Timeout(1000L)
    fun execute_negpage() {
        val op = CountingPageOperation(-1, Long.MAX_VALUE)
        op.execute()

        assertEquals(0L, op.counter)
    }

    @Test
    @Timeout(1000L)
    fun execute_npage() {
        val n = 7
        val op = CountingPageOperation(n, Long.MAX_VALUE)
        op.execute()

        assertEquals(n * 10L, op.counter)
    }

    @Test
    @Timeout(1000L)
    fun execute_nullpage() {
        val op: CountingPageOperation = NullPageCountingPageOperation(Int.MAX_VALUE, Long.MAX_VALUE)
        op.execute()

        assertEquals(0L, op.counter)
    }

    @Test
    @Timeout(1000L)
    fun execute_emptypage() {
        val op: CountingPageOperation = EmptyPageCountingPageOperation(Int.MAX_VALUE, Long.MAX_VALUE)
        op.execute()

        assertEquals(0L, op.counter)
    }

    @Test
    @Timeout(1000L)
    fun execute_zerotime() {
        val op = CountingPageOperation(Int.MAX_VALUE, 0L)
        op.execute()

        assertEquals(0L, op.counter)
        assertEquals(0L, op.timeToLastFetch)
    }

    /*
	 * This is a valid test however it is vulnerable to a race condition
	 * as such it is being ignored.
	 */
    @Test
    @Timeout(1000L)
    @Disabled("Vulnerable to a race condition")
    fun execute_nonzerotime() {
        val timeMillis = 200L
        val op = CountingPageOperation(Int.MAX_VALUE, timeMillis)
        op.execute()

        assertFalse(
            op.timeToLastFetch > timeMillis
                    && op.timeToPreviousFetch > timeMillis,
            "last fetch time " + op.timeToLastFetch + "" +
                    " and previous fetch time  " + op.timeToPreviousFetch +
                    " exceed max time" + timeMillis,
        )
    }

    @Test
    @Timeout(1000L)
    fun execute_negtime() {
        val timeMillis = -100L
        val op = CountingPageOperation(Int.MAX_VALUE, timeMillis)
        op.execute()

        assertEquals(0L, op.counter)
    }

    @Test
    @Timeout(1000L)
    fun execute_swallowException() {
        val op: CountingPageOperation = EvenExceptionCountingPageOperation(1, 1000L)
        op.execute()

        assertTrue(op.isSwallowExceptions)
        assertEquals(5L, op.counter)
    }

    @Test
    fun execute_noSwallowException() {
        assertThrows<IllegalStateException> {
            val op: CountingPageOperation = EvenExceptionCountingPageOperation(1, 1000L)
            op.isSwallowExceptions = false

            try {
                op.execute()
            } finally {
                assertEquals(1L, op.counter)
            }
        }
    }


    private open class CountingPageOperation(maxPages: Int, maxTime: Long) :
        AbstractPageOperationTemplate<String?>("CountingPageOperation", maxPages, maxTime) {

        private var currentPageFetch = 0
        private val pageSize = 10

        var counter: Long = 0L
            private set
        private val startTime = System.currentTimeMillis()
        var timeToLastFetch: Long = 0
            private set
        var timeToPreviousFetch: Long = 0
            private set

        override fun fetchPage(): Collection<String>? {
            timeToPreviousFetch = if (timeToLastFetch > 0) timeToLastFetch else 0
            timeToLastFetch = System.currentTimeMillis() - startTime

            val page: MutableList<String> = ArrayList(pageSize)
            for (i in 0 until pageSize) {
                page.add("item " + currentPageFetch * pageSize + i)
            }
            currentPageFetch++
            return page
        }

        override fun doOperation(item: String?) {
            counter++
        }
    }

    private class NullPageCountingPageOperation(maxPages: Int, maxTime: Long) :
        CountingPageOperation(maxPages, maxTime) {
        override fun fetchPage(): Collection<String>? {
            return null
        }
    }

    private class EmptyPageCountingPageOperation(maxPages: Int, maxTime: Long) :
        CountingPageOperation(maxPages, maxTime) {
        override fun fetchPage(): Collection<String> {
            return ArrayList(0)
        }
    }

    private class EvenExceptionCountingPageOperation(maxPages: Int, maxTime: Long) :
        CountingPageOperation(maxPages, maxTime) {
        private var callCounter = 0
        override fun doOperation(item: String?) {
            callCounter++
            check(callCounter % 2 != 0) { "even number items cannot be processed" }

            super.doOperation(item)
        }
    }
}
