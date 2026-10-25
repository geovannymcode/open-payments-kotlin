package io.github.geovannymcode.openpayments.httpsignatures

import io.github.geovannymcode.openpayments.httpsignatures.jvm.hash

/**
 * Algoritmos de digest de RFC 9530 §5 soportados.
 *
 * @property key clave del algoritmo en el diccionario de `Content-Digest`.
 */
public enum class DigestAlgorithm(public val key: String) {
    SHA_256("sha-256"),
    SHA_512("sha-512"),
}

/**
 * Cálculo del campo `Content-Digest` de RFC 9530.
 *
 * El digest se calcula sobre los bytes exactos del cuerpo; ver [HttpRequest] sobre por qué el
 * cuerpo no debe reserializarse después.
 */
public object ContentDigest {
    /** Nombre del campo. */
    public const val HEADER_NAME: String = "Content-Digest"

    /**
     * Devuelve el valor de `Content-Digest` para [body], con un miembro por algoritmo, en orden;
     * por ejemplo `sha-512=:base64:`.
     */
    public fun headerValue(
        body: ByteArray,
        algorithms: List<DigestAlgorithm> = listOf(DigestAlgorithm.SHA_512),
    ): String {
        require(algorithms.isNotEmpty()) { "Se necesita al menos un algoritmo de digest" }
        return algorithms.distinct().joinToString(", ") {
            "${StructuredFields.key(it.key)}=${StructuredFields.binary(it.hash(body))}"
        }
    }
}

/**
 * Devuelve una copia de la petición con `Content-Digest` calculado sobre su cuerpo, reemplazando
 * cualquier valor previo.
 *
 * @throws IllegalArgumentException si la petición no tiene cuerpo.
 */
public fun HttpRequest.withContentDigest(
    algorithms: List<DigestAlgorithm> = listOf(DigestAlgorithm.SHA_512),
): HttpRequest {
    val bytes = requireNotNull(bodyOrNull()) { "La petición no tiene cuerpo sobre el cual calcular Content-Digest" }
    return replacingHeader(ContentDigest.HEADER_NAME, ContentDigest.headerValue(bytes, algorithms))
}
