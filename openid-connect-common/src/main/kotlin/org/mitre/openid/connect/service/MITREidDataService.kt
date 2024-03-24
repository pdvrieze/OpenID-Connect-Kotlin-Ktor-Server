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
package org.mitre.openid.connect.service

import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonWriter
import java.io.IOException

/**
 * @author jricher
 * @author arielak
 */
interface MITREidDataService {
    /**
     * Write out the current server state to the given JSON writer as a JSON object
     *
     * @throws IOException
     */
    @Throws(IOException::class)
    fun exportData(writer: JsonWriter)

    /**
     * Read in the current server state from the given JSON reader as a JSON object
     */
    @Throws(IOException::class)
    fun importData(reader: JsonReader)

    /**
     * Return true if the this data service supports the given version. This is called before
     * handing the service the reader through its importData function.
     *
     */
    fun supportsVersion(version: String?): Boolean

    companion object {
        /**
         * Data member for 1.X configurations
         */
        const val MITREID_CONNECT_1_0: String = "mitreid-connect-1.0"
        const val MITREID_CONNECT_1_1: String = "mitreid-connect-1.1"
        const val MITREID_CONNECT_1_2: String = "mitreid-connect-1.2"
        const val MITREID_CONNECT_1_3: String = "mitreid-connect-1.3"

        // member names
        const val REFRESHTOKENS: String = "refreshTokens"
        const val ACCESSTOKENS: String = "accessTokens"
        const val WHITELISTEDSITES: String = "whitelistedSites"
        const val BLACKLISTEDSITES: String = "blacklistedSites"
        const val AUTHENTICATIONHOLDERS: String = "authenticationHolders"
        const val GRANTS: String = "grants"
        const val CLIENTS: String = "clients"
        const val SYSTEMSCOPES: String = "systemScopes"
    }
}
