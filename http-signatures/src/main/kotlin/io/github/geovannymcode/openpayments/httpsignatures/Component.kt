package io.github.geovannymcode.openpayments.httpsignatures

/**
 * Componente de la petición cubierto por una firma (RFC 9421 §2).
 *
 * Puede ser un componente derivado (`@method`, `@path`, ...) o un campo HTTP ([Field]).
 *
 * @property name identificador del componente tal como aparece en la signature base.
 */
public sealed class Component(public val name: String) {
    /** `@method`: método HTTP de la petición (§2.2.1). */
    public data object Method : Component("@method")

    /** `@target-uri`: URI de destino completa, sin fragmento (§2.2.2). */
    public data object TargetUri : Component("@target-uri")

    /** `@authority`: host en minúsculas y puerto, omitido si es el del esquema (§2.2.3). */
    public data object Authority : Component("@authority")

    /** `@scheme`: esquema de la URI en minúsculas (§2.2.4). */
    public data object Scheme : Component("@scheme")

    /** `@request-target`: ruta y query en forma de origen (§2.2.5). */
    public data object RequestTarget : Component("@request-target")

    /** `@path`: ruta absoluta; `/` si la URI no tiene ruta (§2.2.6). */
    public data object Path : Component("@path")

    /** `@query`: query con el `?` inicial; solo `?` si la URI no tiene query (§2.2.7). */
    public data object Query : Component("@query")

    /**
     * Campo HTTP identificado por nombre. El nombre se normaliza a minúsculas (§2.1).
     *
     * @param fieldName nombre del campo, por ejemplo `Content-Type`.
     */
    public class Field(fieldName: String) : Component(fieldName.lowercase()) {
        init {
            require(fieldName.isNotEmpty() && !fieldName.startsWith('@') && fieldName.none { it.isWhitespace() || it == ':' }) {
                "Nombre de campo inválido: '$fieldName'"
            }
        }

        override fun equals(other: Any?): Boolean = other is Field && other.name == name

        override fun hashCode(): Int = name.hashCode()

        override fun toString(): String = "Field($name)"
    }
}
