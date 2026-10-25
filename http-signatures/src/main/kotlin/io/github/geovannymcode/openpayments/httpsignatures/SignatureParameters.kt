package io.github.geovannymcode.openpayments.httpsignatures

/**
 * Parámetros de firma de RFC 9421 §2.3, serializados dentro de `@signature-params`.
 *
 * Se serializan en el orden `created`, `expires`, `nonce`, `alg`, `keyid`, `tag`, omitiendo los nulos.
 *
 * [algorithm] es `null` por defecto: Open Payments deriva el algoritmo de la llave publicada en el
 * JWKS del cliente, así que el verificador lo obtiene de la llave y no del mensaje.
 *
 * @property created momento de creación, en segundos desde la época Unix.
 * @property expires momento de expiración, en segundos desde la época Unix.
 * @property nonce valor único para evitar repeticiones.
 * @property algorithm identificador del algoritmo según el registro de RFC 9421, por ejemplo `ed25519`.
 * @property keyId identificador de la llave; en Open Payments, el `kid` publicado en el JWKS.
 * @property tag etiqueta de aplicación.
 */
public class SignatureParameters(
    public val created: Long? = null,
    public val expires: Long? = null,
    public val nonce: String? = null,
    public val algorithm: String? = null,
    public val keyId: String? = null,
    public val tag: String? = null,
) {
    internal fun serialize(): String = buildString {
        created?.let { append(";created=").append(StructuredFields.integer(it)) }
        expires?.let { append(";expires=").append(StructuredFields.integer(it)) }
        nonce?.let { append(";nonce=").append(StructuredFields.string(it)) }
        algorithm?.let { append(";alg=").append(StructuredFields.string(it)) }
        keyId?.let { append(";keyid=").append(StructuredFields.string(it)) }
        tag?.let { append(";tag=").append(StructuredFields.string(it)) }
    }

    override fun toString(): String = "SignatureParameters(${serialize()})"
}
