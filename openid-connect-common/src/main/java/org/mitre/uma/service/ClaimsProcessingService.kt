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
package org.mitre.uma.service

import org.mitre.uma.model.ClaimProcessingResult
import org.mitre.uma.model.PermissionTicket
import org.mitre.uma.model.ResourceSet

/**
 *
 * Processes claims presented during an UMA transaction.
 *
 * @author jricher
 */
interface ClaimsProcessingService {
    /**
     * Determine whether or not the claims that have been supplied are
     * sufficient to fulfill the requirements given by the claims that
     * are required.
     *
     * @param rs the required claims to check against
     * @param ticket the supplied claims to test
     * @return the result of the claims processing action
     */
    fun claimsAreSatisfied(rs: ResourceSet?, ticket: PermissionTicket?): ClaimProcessingResult?
}
