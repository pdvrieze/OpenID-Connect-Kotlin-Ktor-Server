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
import java.time.format.DateTimeFormatterBuilder
import java.time.temporal.ChronoField
import java.util.*

typealias ISODate = @Serializable(IsoDateSerializer::class) Date

object IsoDateSerializer : KSerializer<Date> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("java.util.Date.ISO", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: Date) {
        encoder.encodeString(dateFormatter.format(value.toInstant().atZone(UTC_ZONE)))
    }

    override fun deserialize(decoder: Decoder): Date {
        return Date.from(Instant.from(dateFormatter.parse(decoder.decodeString())))
    }

    private val dateFormatter: DateTimeFormatter = DateTimeFormatterBuilder()
        .parseCaseInsensitive()
        .append(DateTimeFormatter.ISO_LOCAL_DATE)
        .appendLiteral('T')
        .appendValue(ChronoField.HOUR_OF_DAY, 2)
        .appendLiteral(':')
        .appendValue(ChronoField.MINUTE_OF_HOUR, 2)
        .optionalStart()
        .appendLiteral(':')
        .appendValue(ChronoField.SECOND_OF_MINUTE, 2)
        .parseLenient()
        .optionalStart()
        .appendFraction(ChronoField.NANO_OF_SECOND, 3, 3, true)
        .optionalEnd()
        .appendOffsetId()
        .parseStrict()
        .toFormatter()

    private val UTC_ZONE = ZoneId.of("UTC")

}
