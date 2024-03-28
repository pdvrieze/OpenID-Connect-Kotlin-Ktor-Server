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
package org.mitre.openid.connect.client.keypublisher

import com.google.common.base.Strings
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.openid.connect.view.JWKSetView
import org.springframework.beans.BeansException
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory
import org.springframework.beans.factory.support.BeanDefinitionBuilder
import org.springframework.beans.factory.support.BeanDefinitionRegistry
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor
import org.springframework.web.servlet.ModelAndView
import java.util.*

/**
 * @author jricher
 */
class ClientKeyPublisher : BeanDefinitionRegistryPostProcessor {
    lateinit var signingAndValidationService: JWTSigningAndValidationService

    var jwkPublishUrl: String? = null

    private lateinit var registry: BeanDefinitionRegistry

    private var jwkViewName = JWKSetView.VIEWNAME

    /**
     * If the jwkPublishUrl field is set on this bean, set up a listener on that URL to publish keys.
     */
    @Throws(BeansException::class)
    override fun postProcessBeanFactory(beanFactory: ConfigurableListableBeanFactory) {
        if (!Strings.isNullOrEmpty(jwkPublishUrl)) {
            // add a mapping to this class

            val clientKeyMapping = BeanDefinitionBuilder.rootBeanDefinition(ClientKeyPublisherMapping::class.java)
            // custom view resolver
            val viewResolver = BeanDefinitionBuilder.rootBeanDefinition(JwkViewResolver::class.java)

            if (!Strings.isNullOrEmpty(jwkPublishUrl)) {
                clientKeyMapping.addPropertyValue("jwkPublishUrl", jwkPublishUrl)

                // randomize view name to make sure it doesn't conflict with local views
                jwkViewName = JWKSetView.VIEWNAME + "-" + UUID.randomUUID().toString()
                viewResolver.addPropertyValue("jwkViewName", jwkViewName)

                // view bean
                val jwkView = BeanDefinitionBuilder.rootBeanDefinition(JWKSetView::class.java)
                registry.registerBeanDefinition(JWKSetView.VIEWNAME, jwkView.beanDefinition)
                viewResolver.addPropertyReference("jwk", JWKSetView.VIEWNAME)
            }

            registry.registerBeanDefinition("clientKeyMapping", clientKeyMapping.beanDefinition)
            registry.registerBeanDefinition("jwkViewResolver", viewResolver.beanDefinition)
        }
    }

    /* (non-Javadoc)
	 * @see org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor#postProcessBeanDefinitionRegistry(org.springframework.beans.factory.support.BeanDefinitionRegistry)
	 */
    @Throws(BeansException::class)
    override fun postProcessBeanDefinitionRegistry(registry: BeanDefinitionRegistry) {
        this.registry = registry
    }

    /**
     * Return a view to publish all keys in JWK format. Only used if jwkPublishUrl is set.
     */
    fun publishClientJwk(): ModelAndView {
        // map from key id to key

        val keys = signingAndValidationService.allPublicKeys

        return ModelAndView(jwkViewName, "keys", keys)
    }
}
