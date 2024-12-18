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

import org.mitre.jwt.signer.service.JWTSigningAndValidationService

/**
 * @author jricher
 */
class ClientKeyPublisher(
    var signingAndValidationService: JWTSigningAndValidationService
) {

    var jwkPublishUrl: String? = null

//    private lateinit var registry: BeanDefinitionRegistry

    private var jwkViewName = JWK_SET_VIEW_NAME

    /**
     * If the jwkPublishUrl field is set on this bean, set up a listener on that URL to publish keys.
     */
/*
    override fun postProcessBeanFactory(beanFactory: ConfigurableListableBeanFactory) {
        return
        if (!jwkPublishUrl.isNullOrEmpty()) {
            // add a mapping to this class

            val clientKeyMapping = BeanDefinitionBuilder.rootBeanDefinition(ClientKeyPublisherMapping::class.java)
            // custom view resolver
            val viewResolver = BeanDefinitionBuilder.rootBeanDefinition(JwkViewResolver::class.java)

            if (!jwkPublishUrl.isNullOrEmpty()) {
                clientKeyMapping.addPropertyValue("jwkPublishUrl", jwkPublishUrl)

                // randomize view name to make sure it doesn't conflict with local views
                jwkViewName = JWK_SET_VIEW_NAME + "-" + UUID.randomUUID().toString()
                viewResolver.addPropertyValue("jwkViewName", jwkViewName)

                // view bean
                val jwkView = BeanDefinitionBuilder.rootBeanDefinition(org.mitre.openid.connect.view.JWKSetView::class.java)
                registry.registerBeanDefinition(JWK_SET_VIEW_NAME, jwkView.beanDefinition)
                viewResolver.addPropertyReference("jwk", JWK_SET_VIEW_NAME)
            }

            registry.registerBeanDefinition("clientKeyMapping", clientKeyMapping.beanDefinition)
            registry.registerBeanDefinition("jwkViewResolver", viewResolver.beanDefinition)
        }
    }
*/

    /* (non-Javadoc)
	 * @see org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor#postProcessBeanDefinitionRegistry(org.springframework.beans.factory.support.BeanDefinitionRegistry)
	 */
/*
    @Throws(BeansException::class)
    override fun postProcessBeanDefinitionRegistry(registry: BeanDefinitionRegistry) {
        this.registry = registry
    }
*/

    /**
     * Return a view to publish all keys in JWK format. Only used if jwkPublishUrl is set.
     */
/*
    fun publishClientJwk(): ModelAndView {
        // map from key id to key

        val keys = signingAndValidationService.allPublicKeys

        return ModelAndView(jwkViewName, "keys", keys)
    }
*/

    companion object {
        const val JWK_SET_VIEW_NAME = "jwkSet"
    }

}
