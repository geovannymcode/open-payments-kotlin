package io.github.geovannymcode.openpayments.httpsignatures

/**
 * Colección inmutable de campos HTTP.
 *
 * Los nombres se comparan sin distinguir mayúsculas y un mismo nombre puede repetirse:
 * cada aparición se conserva como una línea de campo independiente y en su orden original,
 * porque RFC 9421 §2.1 exige unirlas en ese orden al construir la signature base.
 */
public class HttpHeaders private constructor(
    private val fields: List<Pair<String, String>>,
) {
    /** Nombres de campo en minúsculas, en orden de primera aparición. */
    public val names: Set<String>
        get() = fields.mapTo(LinkedHashSet()) { it.first.lowercase() }

    /** Devuelve todos los valores del campo [name], en orden, o una lista vacía si no existe. */
    public fun values(name: String): List<String> =
        fields.filter { it.first.equals(name, ignoreCase = true) }.map { it.second }

    /** Indica si existe al menos una línea del campo [name]. */
    public operator fun contains(name: String): Boolean =
        fields.any { it.first.equals(name, ignoreCase = true) }

    /** Devuelve una copia con una línea adicional `name: value`, conservando las existentes. */
    public fun with(name: String, value: String): HttpHeaders {
        requireValidName(name)
        return HttpHeaders(fields + (name to value))
    }

    /** Devuelve una copia en la que [name] tiene un único valor [value]. */
    public fun replacing(name: String, value: String): HttpHeaders {
        requireValidName(name)
        return HttpHeaders(fields.filterNot { it.first.equals(name, ignoreCase = true) } + (name to value))
    }

    /** Devuelve las líneas de campo tal como se agregaron, con el nombre original. */
    public fun toList(): List<Pair<String, String>> = fields

    override fun equals(other: Any?): Boolean = other is HttpHeaders && other.fields == fields

    override fun hashCode(): Int = fields.hashCode()

    override fun toString(): String = fields.joinToString(prefix = "HttpHeaders(", postfix = ")") { "${it.first}: ${it.second}" }

    public companion object {
        /** Colección sin campos. */
        public val EMPTY: HttpHeaders = HttpHeaders(emptyList())

        /** Crea una colección a partir de pares `nombre to valor`; los nombres repetidos se conservan. */
        public fun of(vararg fields: Pair<String, String>): HttpHeaders {
            fields.forEach { requireValidName(it.first) }
            return HttpHeaders(fields.toList())
        }

        private fun requireValidName(name: String) {
            require(name.isNotEmpty() && name.none { it.isWhitespace() || it == ':' }) {
                "Nombre de campo HTTP inválido: '$name'"
            }
        }
    }
}
