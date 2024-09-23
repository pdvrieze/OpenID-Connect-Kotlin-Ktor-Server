package org.mitre.openid.connect.config

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.InjectMocks
import org.mockito.Spy
import org.mockito.junit.jupiter.MockitoExtension
import org.springframework.core.io.ClassPathResource
import org.springframework.core.io.Resource
import java.util.*

@ExtendWith(MockitoExtension::class)
class TestJsonMessageSource {
    @InjectMocks
    private lateinit var jsonMessageSource: JsonMessageSource

    @Spy
    private lateinit var config: ConfigurationPropertiesBean

    private val localeThatHasAFile = Locale("en")

    private val localeThatDoesNotHaveAFile = Locale("xx")

    @BeforeEach
    fun setup() {
        //test message files are located in test/resources/js/locale/
        val resource: Resource = ClassPathResource("/resources/js/locale/")
        jsonMessageSource.baseDirectory = resource
    }

    @Test
    fun verifyWhenLocaleExists_canResolveCode() {
        val mf = jsonMessageSource.resolveCode("testAttribute", localeThatHasAFile)!!
        assertEquals(mf.locale.language, "en")
        assertEquals(mf.toPattern(), "testValue")
    }

    @Test
    fun verifyWhenLocaleDoesNotExist_cannotResolveCode() {
        val mf = jsonMessageSource.resolveCode("test", localeThatDoesNotHaveAFile)
        assertNull(mf)
    }
}
