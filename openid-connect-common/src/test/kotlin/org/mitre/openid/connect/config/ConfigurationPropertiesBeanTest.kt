/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
 *
 * Portions copyright 2011-2013 The MITRE Corporation
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
package org.mitre.openid.connect.config

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/**
 * @author jricher
 */
class ConfigurationPropertiesBeanTest {
    /**
     * Test getters and setters for configuration object.
     */
    @Test
    fun testConfigurationPropertiesBean() {
        // make sure the values that go in come back out unchanged

        val bean = ConfigurationPropertiesBean()

        val iss = "http://localhost:8080/openid-connect-server/"
        val title = "OpenID Connect Server"
        val logoUrl = "/images/logo.png"

        bean.issuer = iss
        bean.topbarTitle = title
        bean.logoImageUrl = logoUrl
        bean.isForceHttps = true

        assertEquals(iss, bean.issuer)
        assertEquals(title, bean.topbarTitle)
        assertEquals(logoUrl, bean.logoImageUrl)
        assertEquals(true, bean.isForceHttps)
    }

    @Test
    fun testCheckForHttpsIssuerHttpDefaultFlag() {
        val bean = ConfigurationPropertiesBean()

        // issuer is http
        // leave as default, which is unset/false
        try {
            bean.issuer = "http://localhost:8080/openid-connect-server/"
            bean.checkConfigConsistency()
        } catch (e: Exception) {
            fail("Unexpected BeanCreationException for http issuer with default forceHttps, message:" + e.message, e)
        }
    }

    @Test
    fun testCheckForHttpsIssuerHttpFalseFlag() {
        val bean = ConfigurationPropertiesBean()
        // issuer is http
        // set to false
        try {
            bean.issuer = "http://localhost:8080/openid-connect-server/"
            bean.isForceHttps = false
            bean.checkConfigConsistency()
        } catch (e: Exception) {
            fail("Unexpected BeanCreationException for http issuer with forceHttps=false, message:" + e.message, e)
        }
    }

    @Test
    fun testCheckForHttpsIssuerHttpTrueFlag() {
        assertThrows<IllegalStateException> {
            val bean = ConfigurationPropertiesBean()
            // issuer is http
            // set to true
            bean.issuer = "http://localhost:8080/openid-connect-server/"
            bean.isForceHttps = true
            bean.checkConfigConsistency()
        }
    }

    @Test
    fun testCheckForHttpsIssuerHttpsDefaultFlag() {
        val bean = ConfigurationPropertiesBean()
        // issuer is https
        // leave as default, which is unset/false
        try {
            bean.issuer = "https://localhost:8080/openid-connect-server/"
            bean.checkConfigConsistency()
        } catch (e: Exception) {
            fail("Unexpected BeanCreationException for https issuer with default forceHttps, message:" + e.message, e)
        }
    }

    @Test
    fun testCheckForHttpsIssuerHttpsFalseFlag() {
        val bean = ConfigurationPropertiesBean()
        // issuer is https
        // set to false
        try {
            bean.issuer = "https://localhost:8080/openid-connect-server/"
            bean.isForceHttps = false
            bean.checkConfigConsistency()
        } catch (e: Exception) {
            fail("Unexpected BeanCreationException for https issuer with forceHttps=false, message:" + e.message, e)
        }
    }

    @Test
    fun testCheckForHttpsIssuerHttpsTrueFlag() {
        val bean = ConfigurationPropertiesBean()
        // issuer is https
        // set to true
        try {
            bean.issuer = "https://localhost:8080/openid-connect-server/"
            bean.isForceHttps = true
            bean.checkConfigConsistency()
        } catch (e: Exception) {
            fail("Unexpected BeanCreationException for https issuer with forceHttps=true, message:" + e.message, e)
        }
    }

    @Test
    fun testShortTopbarTitle() {
        val bean = ConfigurationPropertiesBean()
        bean.topbarTitle = "LONG"
        assertEquals("LONG", bean.shortTopbarTitle)
        bean.shortTopbarTitle = "SHORT"
        assertEquals("SHORT", bean.shortTopbarTitle)
    }
}
