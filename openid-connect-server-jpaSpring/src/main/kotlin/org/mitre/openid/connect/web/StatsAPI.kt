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
package org.mitre.openid.connect.web

import org.mitre.openid.connect.service.StatsService
import org.mitre.openid.connect.view.JsonEntityView
import org.mitre.util.getLogger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Controller
import org.springframework.ui.ModelMap
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping

@Controller
@RequestMapping("/" + StatsAPI.URL)
class StatsAPI {
    @Autowired
    private lateinit var statsService: StatsService

    @RequestMapping(value = ["summary"], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun statsSummary(m: ModelMap): String {
        val e = statsService.summaryStats

        m[JsonEntityView.ENTITY] = e

        return JsonEntityView.VIEWNAME
    }

    //	@PreAuthorize("hasRole('ROLE_USER')")
    //	@RequestMapping(value = "byclientid", produces = MediaType.APPLICATION_JSON_VALUE)
    //	public String statsByClient(ModelMap m) {
    //		Map<Long, Integer> e = statsService.getByClientId();
    //
    //		m.put(JsonEntityView.ENTITY, e);
    //
    //		return JsonEntityView.VIEWNAME;
    //	}
    //
    @PreAuthorize("hasRole('ROLE_USER')")
    @RequestMapping(value = ["byclientid/{id}"], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun statsByClientId(@PathVariable("id") clientId: String?, m: ModelMap): String {
        val e = statsService.getCountForClientId(clientId!!)

        m[JsonEntityView.ENTITY] = e

        return JsonEntityView.VIEWNAME
    }

    companion object {
        const val URL: String = RootController.API_URL + "/stats"

        // Logger for this class
        private val logger = getLogger<StatsAPI>()
    }
}
