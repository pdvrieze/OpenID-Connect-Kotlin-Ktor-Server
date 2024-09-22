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
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Controller
import org.springframework.ui.ModelMap
import org.springframework.web.bind.annotation.RequestMapping

/**
 * @author Michael Jett <mjett></mjett>@mitre.org>
 */
@Controller
class RootController {
    @Autowired
    var statsService: StatsService? = null

    @RequestMapping(value = ["", "home", "index"])
    fun showHomePage(m: ModelMap?): String {
        return "home"
    }

    @RequestMapping(value = ["about", "about/"])
    fun showAboutPage(m: ModelMap?): String {
        return "about"
    }

    @RequestMapping(value = ["stats", "stats/"])
    fun showStatsPage(m: ModelMap): String {
        val summary = statsService!!.summaryStats

        m["statsSummary"] = summary
        return "stats"
    }

    @RequestMapping(value = ["contact", "contact/"])
    fun showContactPage(m: ModelMap?): String {
        return "contact"
    }

    @PreAuthorize("hasRole('ROLE_USER')")
    @RequestMapping("manage/**")
    fun showClientManager(m: ModelMap?): String {
        return "manage"
    }

    companion object {
        const val API_URL: String = "api"
    }
}
