package io.github.geovannymcode.openpayments.httpsignatures

import kotlin.io.encoding.Base64

/**
 * Serialización de RFC 8941 (Structured Field Values) limitada a lo que necesitan RFC 9421 y
 * RFC 9530. No incluye parser: este módulo solo produce valores, no los interpreta.
 */
internal object StructuredFields {
    private const val MAX_INTEGER = 999_999_999_999_999L
    private val KEY = Regex("[a-z*][a-z0-9_.*-]*")

    /** sf-string (§4.1.6): solo ASCII imprimible, escapando `\` y `"`. */
    fun string(value: String): String {
        require(value.all { it in ' '..'~' }) { "Un sf-string solo admite ASCII imprimible: '$value'" }
        return buildString(value.length + 2) {
            append('"')
            value.forEach {
                if (it == '\\' || it == '"') append('\\')
                append(it)
            }
            append('"')
        }
    }

    /** sf-integer (§4.1.4): entero decimal de hasta 15 dígitos. */
    fun integer(value: Long): String {
        require(value in -MAX_INTEGER..MAX_INTEGER) { "Un sf-integer debe tener como máximo 15 dígitos: $value" }
        return value.toString()
    }

    /** sf-binary (§4.1.8): base64 estándar con relleno, entre dos puntos. */
    fun binary(value: ByteArray): String = ":${Base64.encode(value)}:"

    /** key (§4.1.1.3) usada en parámetros y miembros de diccionario. */
    fun key(value: String): String {
        require(KEY.matches(value)) { "Clave de Structured Field inválida: '$value'" }
        return value
    }
}
