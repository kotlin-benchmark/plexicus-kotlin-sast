package com.plexicus.demo.model

/** Generic data request envelope used by DataController demos. */
data class DataRequest(
    val url: String? = null,
    val xml: String? = null,
    val payloadBase64: String? = null,
    val templateName: String? = null,
    val archivePath: String? = null
)
