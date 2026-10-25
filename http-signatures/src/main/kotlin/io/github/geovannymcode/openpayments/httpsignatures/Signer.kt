package io.github.geovannymcode.openpayments.httpsignatures

/**
 * Produce la firma criptográfica de una signature base.
 *
 * Está separado de cualquier implementación concreta para que el módulo pueda portarse a
 * Kotlin Multiplatform: cada target aporta su propio [Signer] (en JVM,
 * [io.github.geovannymcode.openpayments.httpsignatures.jvm.Ed25519Signer]).
 */
public fun interface Signer {
    /** Firma los bytes de [signatureBase] y devuelve la firma en bruto, sin codificar. */
    public fun sign(signatureBase: ByteArray): ByteArray
}
