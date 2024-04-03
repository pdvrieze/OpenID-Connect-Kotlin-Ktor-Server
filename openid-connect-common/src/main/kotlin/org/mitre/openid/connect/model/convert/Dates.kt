package org.mitre.openid.connect.model.convert

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import org.springframework.format.annotation.DateTimeFormat
import org.springframework.format.datetime.DateFormatter
import java.util.*

typealias ISODate = @Serializable(IsoDateSerializer::class) Date

object IsoDateSerializer : KSerializer<Date> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("java.util.Date.ISO", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: Date) {
        encoder.encodeString(dateFormatter.print(value, Locale.ENGLISH))
    }

    override fun deserialize(decoder: Decoder): Date {
        return dateFormatter.parse(decoder.decodeString(), Locale.ENGLISH)
    }

    private val dateFormatter = DateFormatter().apply {
        setIso(DateTimeFormat.ISO.DATE_TIME)
    }

}
