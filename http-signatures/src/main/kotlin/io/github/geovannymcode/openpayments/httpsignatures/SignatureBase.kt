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
    /**
     * Bytes US-ASCII de [value], que son la entrada del [Signer].
     *
     * Se codifica a mano en lugar de usar `Charsets.US_ASCII`, que es `java.nio.charset` y no
     * existe fuera de la JVM. [of] ya garantiza que todo carácter es ASCII.
     */
    public fun toByteArray(): ByteArray = ByteArray(value.length) { index ->
        val char = value[index]
        check(char.code < 0x80) { "La signature base contiene un carácter no ASCII en la posición $index" }
        char.code.toByte()
    }

    override fun toString(): String = value

    public companion object {
        private const val SIGNATURE_PARAMS = "@signature-params"

        /**
         * Construye la signature base de [request] cubriendo [components] en ese orden.
         *
         * @throws IllegalArgumentException si un componente se repite, si un campo cubierto no
         * existe en la petición, si el valor de un campo contiene saltos de línea o caracteres no
         * ASCII (la codificación con `;bs` de §2.1.3 está fuera de alcance), o si el valor
         * normalizado de un componente derivado no es ASCII imprimible (§2.2).
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
                    append(StructuredFields.string(component.name)).append(": ").append(componentValue).append('\n')
                }
                append(StructuredFields.string(SIGNATURE_PARAMS)).append(": ").append(signatureParams)
            }
            return SignatureBase(components.toList(), parameters, signatureParams, value)
        }

        private fun Component.valueIn(request: HttpRequest): String {
            val target = request.target
            val derivedValue = when (this) {
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
                    val fieldValue = canonicalizeFieldValues(values)
                    requireValidFieldValue(name, fieldValue)
                    return fieldValue
                }
            }
            requireValidDerivedValue(name, derivedValue)
            return derivedValue
        }

        /** Un campo canonicalizado admite ASCII visible, espacio y tabulador (RFC 9110 §5.5). */
        private fun requireValidFieldValue(name: String, value: String) {
            require('\n' !in value && '\r' !in value) { "El valor del campo $name contiene saltos de línea" }
            require(value.all { it == '\t' || it in ' '..'~' }) {
                "El valor del campo $name contiene caracteres no ASCII; la codificación de valores no " +
                    "ASCII (parámetro ;bs de RFC 9421 §2.1.3) está fuera de alcance en esta versión"
            }
        }

        /** Un componente derivado ya normalizado solo admite caracteres imprimibles y espacios (§2.2). */
        private fun requireValidDerivedValue(name: String, value: String) {
            require(value.all { it in ' '..'~' }) {
                "El valor normalizado de $name debe ser ASCII imprimible: '$value'"
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
