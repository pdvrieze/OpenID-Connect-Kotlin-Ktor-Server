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
package org.mitre.openid.connect.client.service.impl

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromStream
import kotlinx.serialization.json.encodeToStream
import org.mitre.oauth2.model.RegisteredClient
import org.mitre.openid.connect.client.service.RegisteredClientService
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException

/**
 * @author jricher
 */
class JsonFileRegisteredClientService(filename: String) : RegisteredClientService {
    private val file = File(filename)

    private var clients: MutableMap<String, RegisteredClient> = HashMap()

    init {
        load()
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.client.service.RegisteredClientService#getByIssuer(java.lang.String)
	 */
    override fun getByIssuer(issuer: String): RegisteredClient? {
        return clients[issuer]
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.client.service.RegisteredClientService#save(java.lang.String, org.mitre.oauth2.model.RegisteredClient)
	 */
    override fun save(issuer: String, client: RegisteredClient) {
        clients[issuer] = client
        write()
    }

    /**
     * Sync the map of clients out to disk.
     */
    private fun write() {
        try {
            if (!file.exists()) {
                // create a new file
                logger.info("Creating saved clients list in $file")
                file.createNewFile()
            }

            FileOutputStream(file).use { out ->
                Json { prettyPrint = true }.encodeToStream(clients, out)
            }
        } catch (e: IOException) {
            logger.error("Could not write to output file", e)
        }
    }

    /**
     * Load the map in from disk.
     */
    private fun load() {
        try {
            if (!file.exists()) {
                logger.info("No sved clients file found in $file")
                return
            }
            FileInputStream(file).use { reader ->
                clients = Json.decodeFromStream(reader)
            }
        } catch (e: IOException) {
            logger.error("Could not read from input file", e)
        }
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(JsonFileRegisteredClientService::class.java)
    }
}
