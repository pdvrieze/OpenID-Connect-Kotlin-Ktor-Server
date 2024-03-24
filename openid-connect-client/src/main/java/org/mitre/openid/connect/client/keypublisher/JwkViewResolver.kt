/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
 *
 * Portions copyright 2011-2013 The MITRE Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package org.mitre.openid.connect.client.keypublisher;

import org.springframework.core.Ordered;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.ViewResolver;

import java.util.Locale;

/**
 *
 * Simple view resolver to map JWK view names to appropriate beans
 *
 * @author jricher
 *
 */
public class JwkViewResolver implements ViewResolver, Ordered {

	private String jwkViewName = "jwkKeyList";
	private View jwk;

	private int order = HIGHEST_PRECEDENCE; // highest precedence, most specific -- avoids hitting the catch-all view resolvers

	/**
	 * Map "jwkKeyList" to the jwk property on this bean.
	 * Everything else returns null
	 */
	@Override
	public View resolveViewName(String viewName, Locale locale) throws Exception {
		if (viewName != null) {
			if (viewName.equals(getJwkViewName())) {
				return getJwk();
			} else {
				return null;
			}
		} else {
			return null;
		}
	}

	public View getJwk() {
		return jwk;
	}

	public void setJwk(View jwk) {
		this.jwk = jwk;
	}

	@Override
	public int getOrder() {
		return order;
	}

	public void setOrder(int order) {
		this.order = order;
	}

	public String getJwkViewName() {
		return jwkViewName;
	}

	public void setJwkViewName(String jwkViewName) {
		this.jwkViewName = jwkViewName;
	}

}
