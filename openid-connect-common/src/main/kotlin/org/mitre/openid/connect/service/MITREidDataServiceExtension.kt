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
package org.mitre.openid.connect.service

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import java.io.IOException

/**
 * A modular extension to the data import/export layer. Any instances of this need to be
 * declared as beans to be picked up by the data services.
 *
 * @author jricher
 */
interface MITREidDataServiceExtension {
    /**
     * Export any data for this extension. This is called from the top level object.
     * All extensions MUST return the writer to a state such that another member of
     * the top level object can be written next.
     */
    @Throws(IOException::class)
    fun exportExtensionData(): JsonObject

    /**
     * Import data that's part of this extension. This is called from the context of
     * reading the top level object. All extensions MUST return the reader to a state
     * such that another member of the top level object can be read next. The name of
     * the data element being imported is passed in as name. If the extension does not
     * support this data element, it must return without advancing the reader.
     *
     * Returns "true" if the item was processed, "false" otherwise.
     */
    @Throws(IOException::class)
    fun importExtensionData(name: String?, data: JsonElement): Boolean

    /**
     * Signal the extension to wrap up all object processing and finalize its
     */
    fun fixExtensionObjectReferences(maps: IMITREidDataServiceMaps)

    /**
     * Return
     */
    fun supportsVersion(version: String): Boolean
}
