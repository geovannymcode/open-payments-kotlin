package io.github.geovannymcode.openpayments.httpsignatures

/**
 * Petición HTTP mínima sobre la que se calculan firmas y digests.
 *
 * Es una abstracción propia para que el módulo sirva con cualquier cliente HTTP (Ktor, OkHttp,
 * `java.net.http`, etc.): cada integración convierte su petición a este tipo antes de firmar.
 *
 * El cuerpo se recibe **ya serializado en bytes** a propósito. `Content-Digest` se calcula sobre
 * esos bytes exactos; si el cliente HTTP volviera a serializar el JSON después (otro orden de
 * claves, otros espacios, otro escape de caracteres), los bytes enviados ya no coincidirían con el
 * digest firmado y el servidor rechazaría la firma. Quien integra debe enviar exactamente
 * [body], sin dejar que el cliente lo reserialice.
 *
 * @property method método HTTP tal como se envía (por ejemplo `POST`).
 * @property uri URI absoluta de destino, por ejemplo `https://wallet.example/incoming-payments`.
 * @property headers campos de la petición.
 */
public class HttpRequest(
    public val method: String,
    public val uri: String,
    public val headers: HttpHeaders = HttpHeaders.EMPTY,
    body: ByteArray? = null,
) {
    private val bodyBytes: ByteArray? = body?.copyOf()

    internal val target: ParsedUri = ParsedUri.parse(uri)

    init {
        require(method.isNotEmpty() && method.none { it.isWhitespace() }) { "Método HTTP inválido: '$method'" }
    }

    /** Copia del cuerpo serializado, o `null` si la petición no tiene cuerpo. */
    public val body: ByteArray?
        get() = bodyBytes?.copyOf()

    /** Devuelve una copia con una línea de campo adicional. */
    public fun withHeader(name: String, value: String): HttpRequest = copy(headers = headers.with(name, value))

    /** Devuelve una copia en la que [name] tiene un único valor [value]. */
    public fun replacingHeader(name: String, value: String): HttpRequest = copy(headers = headers.replacing(name, value))

    internal fun bodyOrNull(): ByteArray? = bodyBytes

    private fun copy(headers: HttpHeaders): HttpRequest = HttpRequest(method, uri, headers, bodyBytes)

    override fun toString(): String = "HttpRequest($method $uri, $headers, body=${bodyBytes?.size ?: 0} bytes)"
}
