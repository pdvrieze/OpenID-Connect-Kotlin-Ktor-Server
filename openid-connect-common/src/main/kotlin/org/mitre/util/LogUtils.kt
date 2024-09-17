package org.mitre.util

import org.slf4j.Logger
import org.slf4j.LoggerFactory

inline fun <reified T> getLogger(): Logger = LoggerFactory.getLogger(T::class.java)

inline fun <reified T> T.getLogger(): Logger = LoggerFactory.getLogger(T::class.java)

fun getLogger(name: String): Logger = LoggerFactory.getLogger(name)
