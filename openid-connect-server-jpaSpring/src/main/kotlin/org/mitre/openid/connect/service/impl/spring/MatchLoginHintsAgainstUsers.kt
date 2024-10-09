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
package org.mitre.openid.connect.service.impl.spring

import org.mitre.openid.connect.service.LoginHintExtracter
import org.mitre.openid.connect.service.UserInfoService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Component

/**
 * Checks the login hint against the User Info collection, only populates it if a user is found.
 * @author jricher
 */
@Component
class MatchLoginHintsAgainstUsers : LoginHintExtracter {
    @Autowired
    private lateinit var userInfoService: UserInfoService

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.service.LoginHintTester#useHint(java.lang.String)
	 */
    override fun extractHint(loginHint: String?): String? {
        if (loginHint.isNullOrEmpty()) {
            return null
        } else {
            return (userInfoService.getByEmailAddress(loginHint)
                ?: userInfoService.getByUsername(loginHint))?.preferredUsername
        }
    }
}
