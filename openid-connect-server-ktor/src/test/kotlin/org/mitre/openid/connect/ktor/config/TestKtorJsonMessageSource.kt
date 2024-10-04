package org.mitre.openid.connect.ktor.config

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.config.JsonMessageSource
import java.util.*

class TestKtorJsonMessageSource {

    private lateinit var config: ConfigurationPropertiesBean

    private lateinit var jsonMessageSource: JsonMessageSource

    private val localeThatHasAFile = Locale("en")

    private val localeThatDoesNotHaveAFile = Locale("xx")

    @BeforeEach
    fun setup() {
        //test message files are located in test/resources/js/locale/
        config = ConfigurationPropertiesBean("http://localhost:8080/")
        jsonMessageSource = JsonMessageSource("/resources/js/locale", config)
    }

    @Test
    fun verifyWhenLocaleExists_canResolveCode() {
        val mf = checkNotNull(jsonMessageSource.resolveCode("testAttribute", localeThatHasAFile))
        Assertions.assertEquals(mf.locale.language, "en")
        Assertions.assertEquals(mf.toPattern(), "testValue")
    }

    @Test
    fun verifyWhenLocaleDoesNotExist_cannotResolveCode() {
        val mf = jsonMessageSource.resolveCode("test", localeThatDoesNotHaveAFile)
        Assertions.assertNull(mf)
    }
}
