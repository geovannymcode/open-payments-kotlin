package io.github.geovannymcode.openpayments.httpsignatures

/**
 * Firma peticiones HTTP según RFC 9421 usando el [Signer] recibido.
 */
public class HttpMessageSigner(private val signer: Signer) {
    /**
     * Construye la signature base de [request] y la firma.
     *
     * @param components componentes cubiertos, en orden.
     * @param parameters parámetros de la firma; `alg` se omite salvo que se indique.
     * @param label etiqueta que identifica la firma en `Signature-Input` y `Signature`.
     */
    public fun sign(
        request: HttpRequest,
        components: List<Component>,
        parameters: SignatureParameters,
        label: String = DEFAULT_LABEL,
    ): HttpSignature {
        StructuredFields.key(label)
        val base = SignatureBase.of(request, components, parameters)
        return HttpSignature(label, base, signer.sign(base.toByteArray()))
    }

    public companion object {
        /** Etiqueta usada por defecto, la misma que emplea Open Payments. */
        public const val DEFAULT_LABEL: String = "sig1"
    }
}

/**
 * Resultado de firmar una petición.
 *
 * @property label etiqueta de la firma.
 * @property signatureBase texto firmado; útil para depurar rechazos del servidor.
 */
public class HttpSignature internal constructor(
    public val label: String,
    public val signatureBase: SignatureBase,
    signature: ByteArray,
) {
    private val signatureBytes: ByteArray = signature.copyOf()

    /** Copia de la firma en bruto. */
    public val signature: ByteArray
        get() = signatureBytes.copyOf()

    /** Valor del campo `Signature-Input`, por ejemplo `sig1=("@method");created=1;keyid="k"`. */
    public val signatureInput: String
        get() = "$label=${signatureBase.signatureParams}"

    /** Valor del campo `Signature`, por ejemplo `sig1=:base64:`. */
    public val signatureHeader: String
        get() = "$label=${StructuredFields.binary(signatureBytes)}"

    /**
     * Devuelve una copia de [request] con los campos `Signature-Input` y `Signature` agregados.
     * Las firmas previas se conservan: varias líneas de estos campos forman un único diccionario.
     */
    public fun applyTo(request: HttpRequest): HttpRequest =
        request.withHeader(SIGNATURE_INPUT, signatureInput).withHeader(SIGNATURE, signatureHeader)

    override fun toString(): String = "HttpSignature($signatureInput)"

    public companion object {
        /** Nombre del campo con los metadatos de la firma (RFC 9421 §4.1). */
        public const val SIGNATURE_INPUT: String = "Signature-Input"

        /** Nombre del campo con la firma (RFC 9421 §4.2). */
        public const val SIGNATURE: String = "Signature"
    }
}
