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
    /** Host en minúsculas, sin userinfo. */
    private val host: String,
    /** Puerto tal como aparece en la URI, o vacío si no se indicó. */
    private val port: String,
    /** Ruta tal como llega, o `/` si está vacía. */
    val path: String,
    /** Query sin el `?` inicial, o `null` si la URI no tiene query. */
    val query: String?,
) {
    /**
     * Valor de `@authority` (§2.2.3): host en minúsculas y puerto, omitido cuando es el puerto
     * por defecto del esquema, como exige RFC 9110 §4.2.3.
     */
    val authority: String
        get() = if (port.isEmpty() || port == DEFAULT_PORTS[scheme]) host else "$host:$port"

    /**
     * Valor de `@target-uri` (§2.2.2): la URI de destino completa, con esquema y host en
     * minúsculas, sin userinfo ni fragmento, y **conservando el puerto explícito** aunque sea el
     * puerto por defecto. La omisión del puerto por defecto es una regla de `@authority`, no de
     * `@target-uri`.
     *
     * Nota: la implementación de referencia de Open Payments es TypeScript y probablemente usa
     * `new URL()`, que sí elimina el puerto por defecto. En la práctica las wallet addresses nunca
     * traen puerto explícito, así que los dos comportamientos coinciden; si alguna vez un servidor
     * rechaza una firma por esto, este es el punto a revisar.
     */
    val targetUri: String
        get() = "$scheme://$host${if (port.isEmpty()) "" else ":$port"}$requestTarget"

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
            require(pathAndQuery.all { it in '!'..'~' }) {
                "La ruta y la query deben venir percent-encoded según RFC 3986 (solo ASCII visible): '$uri'"
            }
            val queryStart = pathAndQuery.indexOf('?')
            val (host, port) = splitAuthority(rest.substring(0, authorityEnd), uri)

            return ParsedUri(
                scheme = scheme,
                host = host,
                port = port,
                path = (if (queryStart < 0) pathAndQuery else pathAndQuery.substring(0, queryStart)).ifEmpty { "/" },
                query = if (queryStart < 0) null else pathAndQuery.substring(queryStart + 1),
            )
        }

        /** Separa host (en minúsculas, sin userinfo) y puerto de la autoridad cruda. */
        private fun splitAuthority(rawAuthority: String, uri: String): Pair<String, String> {
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

            return host.lowercase() to port
        }
    }
}
