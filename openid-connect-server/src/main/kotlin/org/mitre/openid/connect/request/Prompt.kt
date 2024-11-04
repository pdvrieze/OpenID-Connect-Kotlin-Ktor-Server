package org.mitre.openid.connect.request

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.util.*

@Serializable
enum class Prompt(val value: String) {
    @SerialName("login")
    LOGIN("login"),
    @SerialName("none")
    NONE("none"),
    @SerialName("consent")
    CONSENT("consent"),
    @SerialName("select_account")
    SELECT_ACCOUNT("select_account"),
    ;

    fun removeFrom(src: Collection<Prompt>?): EnumSet<Prompt>? = when(src) {
        null -> null
        else -> EnumSet.copyOf(src).also { it.remove(this) }
    }


    companion object {

        fun parseSet(list: String): EnumSet<Prompt> {
            return list.splitToSequence(ConnectRequestParameters.PROMPT_SEPARATOR)
                .mapNotNullTo(EnumSet.noneOf(Prompt::class.java)) { p ->
                    Prompt.entries.firstOrNull { it.value == p }
                }
        }
    }
}
