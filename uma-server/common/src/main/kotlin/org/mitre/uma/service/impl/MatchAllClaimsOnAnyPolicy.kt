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
package org.mitre.uma.service.impl

import org.mitre.uma.model.Claim
import org.mitre.uma.model.ClaimProcessingResult
import org.mitre.uma.model.PermissionTicket
import org.mitre.uma.model.ResourceSet

/**
 * Tests if all the claims in the required set have a matching
 * value in the supplied set.
 *
 * @author jricher
 */
class MatchAllClaimsOnAnyPolicy : org.mitre.uma.service.ClaimsProcessingService {
    /* (non-Javadoc)
	 * @see org.mitre.uma.service.ClaimsProcessingService#claimsAreSatisfied(java.util.Collection, java.util.Collection)
	 */
    override fun claimsAreSatisfied(rs: ResourceSet, ticket: PermissionTicket): ClaimProcessingResult {
        val allUnmatched: MutableCollection<Claim> = HashSet()
        for (policy in rs.policies!!) {
            val unmatched = checkIndividualClaims(policy.claimsRequired!!, ticket.claimsSupplied!!)
            if (unmatched.isEmpty()) {
                // we found something that's satisfied the claims, let's go with it!
                return ClaimProcessingResult(policy)
            } else {
                // otherwise add it to the stack to send back
                allUnmatched.addAll(unmatched)
            }
        }

        // otherwise, tell the caller that we'll need some set of these fulfilled somehow
        return ClaimProcessingResult(allUnmatched)
    }

    private fun checkIndividualClaims(
        claimsRequired: Collection<Claim>,
        claimsSupplied: Collection<Claim>
    ): Collection<Claim> {
        val claimsUnmatched: MutableCollection<Claim> = claimsRequired.toHashSet()

        // see if each of the required claims has a counterpart in the supplied claims set
        for (required in claimsRequired) {
            for (supplied in claimsSupplied) {
                if (required.issuer!!.containsAll(supplied.issuer!!)) {
                    // it's from the right issuer

                    if (required.name == supplied.name && required.value == supplied.value) {
                        // the claim matched, pull it from the set

                        claimsUnmatched.remove(required)
                    }
                }
            }
        }

        // if there's anything left then the claims aren't satisfied, return the leftovers
        return claimsUnmatched
    }
}
