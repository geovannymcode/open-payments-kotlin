package io.github.geovannymcode.openpayments.httpsignatures

/**
 * Signature base de RFC 9421 §2.5: el texto exacto que se firma.
 *
 * Es pública para poder depurar: ante un 401 se compara [value] con la base que reconstruye el
 * servidor, línea por línea. Las líneas se separan con `\n` y la última (`@signature-params`)
 * **no** lleva salto de línea final.
 *
 * @property components componentes cubiertos, en el orden en que aparecen en la base.
 * @property parameters parámetros de la firma.
 * @property signatureParams valor de `@signature-params`; es también el valor que acompaña a la
 * etiqueta en el campo `Signature-Input`.
 * @property value texto completo de la signature base.
 */
public class SignatureBase private constructor(
    public val components: List<Component>,
    public val parameters: SignatureParameters,
    public val signatureParams: String,
    public val value: String,
) {
    /** Bytes UTF-8 de [value], que son la entrada del [Signer]. */
    public fun toByteArray(): ByteArray = value.encodeToByteArray()

    override fun toString(): String = value

    public companion object {
        private const val SIGNATURE_PARAMS = "@signature-params"

        /**
         * Construye la signature base de [request] cubriendo [components] en ese orden.
         *
         * @throws IllegalArgumentException si un componente se repite, si un campo cubierto no
         * existe en la petición o si algún valor contiene saltos de línea.
         */
        public fun of(
            request: HttpRequest,
            components: List<Component>,
            parameters: SignatureParameters,
        ): SignatureBase {
            require(components.toSet().size == components.size) { "Los componentes cubiertos no pueden repetirse: $components" }

            val signatureParams = components.joinToString(" ", prefix = "(", postfix = ")") {
                StructuredFields.string(it.name)
            } + parameters.serialize()

            val value = buildString {
                components.forEach { component ->
                    val componentValue = component.valueIn(request)
                    require('\n' !in componentValue && '\r' !in componentValue) {
                        "El valor de ${component.name} contiene saltos de línea"
                    }
                    append(StructuredFields.string(component.name)).append(": ").append(componentValue).append('\n')
                }
                append(StructuredFields.string(SIGNATURE_PARAMS)).append(": ").append(signatureParams)
            }
            return SignatureBase(components.toList(), parameters, signatureParams, value)
        }

        private fun Component.valueIn(request: HttpRequest): String {
            val target = request.target
            return when (this) {
                Component.Method -> request.method
                Component.TargetUri -> target.targetUri
                Component.Authority -> target.authority
                Component.Scheme -> target.scheme
                Component.RequestTarget -> target.requestTarget
                Component.Path -> target.path
                Component.Query -> "?${target.query.orEmpty()}"
                is Component.Field -> {
                    val values = request.headers.values(name)
                    require(values.isNotEmpty()) { "La petición no tiene el campo cubierto '$name'" }
                    canonicalizeFieldValues(values)
                }
            }
        }
    }
}

private val OBS_FOLD = Regex("[ \\t]*\\r?\\n[ \\t]+")

/**
 * Canonicaliza los valores de un campo según RFC 9421 §2.1: pliega el obs-fold a un espacio,
 * recorta el OWS de cada línea y une las líneas repetidas con `", "`.
 */
internal fun canonicalizeFieldValues(values: List<String>): String =
    values.joinToString(", ") { it.replace(OBS_FOLD, " ").trim(' ', '\t') }
