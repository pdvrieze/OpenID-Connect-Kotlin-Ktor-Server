package io.github.pdvrieze.auth

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
enum class AuthFactor {
    /** User was authenticated using a password. */
    @SerialName("password")
    PASSWORD,
    /** User was authenticated using a one time token. */
    @SerialName("otp")
    OTP,
    /** User was authenticated using a SMS message code. */
    @SerialName("sms")
    SMS,
    /** User was authenticated using a passkey. */
    @SerialName("passkey")
    PASSKEY;
}
