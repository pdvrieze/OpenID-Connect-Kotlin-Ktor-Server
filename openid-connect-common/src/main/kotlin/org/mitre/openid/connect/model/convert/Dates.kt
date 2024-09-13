package org.mitre.openid.connect.model.convert

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.*

typealias ISODate = @Serializable(IsoDateSerializer::class) Date

object IsoDateSerializer : KSerializer<Date> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("java.util.Date.ISO", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: Date) {
        encoder.encodeString(dateFormatter.format(value.toInstant()))
    }

    override fun deserialize(decoder: Decoder): Date {
        return Date.from(Instant.from(dateFormatter.parse(decoder.decodeString())))
    }

    private val dateFormatter: DateTimeFormatter = DateTimeFormatter.ISO_DATE_TIME.withLocale(Locale.ENGLISH).withZone(ZoneId.of("UTC"))

}
