package io.github.geovannymcode.openpayments.httpsignatures

/**
 * URI absoluta descompuesta en las partes que usan los componentes derivados de RFC 9421 §2.2.
 *
 * Se implementa aquí en lugar de usar `java.net.URI` para que el módulo pueda portarse a
 * Kotlin Multiplatform. Solo admite la forma `esquema://autoridad[ruta][?query][#fragmento]`,
 * que es la única válida como destino de una petición firmada.
 */
internal class ParsedUri private constructor(
    /** Esquema en minúsculas. */
    val scheme: String,
    /** Host en minúsculas y puerto, omitido cuando es el puerto por defecto del esquema. */
    val authority: String,
    /** Ruta tal como llega, o `/` si está vacía. */
    val path: String,
    /** Query sin el `?` inicial, o `null` si la URI no tiene query. */
    val query: String?,
) {
    val targetUri: String
        get() = "$scheme://$authority$requestTarget"

    val requestTarget: String
        get() = if (query == null) path else "$path?$query"

    companion object {
        private val SCHEME = Regex("[A-Za-z][A-Za-z0-9+.-]*")
        private val DEFAULT_PORTS = mapOf("http" to "80", "https" to "443")

        fun parse(uri: String): ParsedUri {
            val schemeEnd = uri.indexOf("://")
            require(schemeEnd > 0 && SCHEME.matches(uri.substring(0, schemeEnd))) {
                "La URI debe ser absoluta (esquema://autoridad/ruta): '$uri'"
            }
            val scheme = uri.substring(0, schemeEnd).lowercase()
            val rest = uri.substring(schemeEnd + 3).substringBefore('#')
            val authorityEnd = rest.indexOfFirst { it == '/' || it == '?' }.let { if (it < 0) rest.length else it }
            val pathAndQuery = rest.substring(authorityEnd)
            val queryStart = pathAndQuery.indexOf('?')

            return ParsedUri(
                scheme = scheme,
                authority = normalizeAuthority(scheme, rest.substring(0, authorityEnd), uri),
                path = (if (queryStart < 0) pathAndQuery else pathAndQuery.substring(0, queryStart)).ifEmpty { "/" },
                query = if (queryStart < 0) null else pathAndQuery.substring(queryStart + 1),
            )
        }

        /** Aplica RFC 9110 §4.2.3: host en minúsculas, sin userinfo y sin el puerto por defecto. */
        private fun normalizeAuthority(scheme: String, rawAuthority: String, uri: String): String {
            val hostAndPort = rawAuthority.substringAfterLast('@')
            val portSeparator = if (hostAndPort.startsWith('[')) {
                val closing = hostAndPort.indexOf(']')
                require(closing > 0) { "Literal IPv6 sin cerrar en '$uri'" }
                if (closing + 1 < hostAndPort.length) closing + 1 else -1
            } else {
                hostAndPort.lastIndexOf(':')
            }
            val host = if (portSeparator < 0) hostAndPort else hostAndPort.substring(0, portSeparator)
            val port = if (portSeparator < 0) "" else hostAndPort.substring(portSeparator + 1)

            require(host.isNotEmpty()) { "La URI no tiene host: '$uri'" }
            require(portSeparator < 0 || hostAndPort[portSeparator] == ':') { "Autoridad inválida en '$uri'" }
            require(port.all { it in '0'..'9' }) { "Puerto inválido en '$uri'" }

            val keepPort = port.isNotEmpty() && port != DEFAULT_PORTS[scheme]
            return host.lowercase() + if (keepPort) ":$port" else ""
        }
    }
}
