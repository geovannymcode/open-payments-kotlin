package io.github.geovannymcode.openpayments.httpsignatures.jvm

import io.github.geovannymcode.openpayments.httpsignatures.Signer
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.EdECPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import kotlin.io.encoding.Base64

/**
 * [Signer] Ed25519 sobre `java.security`, que lo incluye de forma nativa desde el JDK 15.
 *
 * Solo para JVM: en otros targets de Kotlin Multiplatform se aporta otro [Signer].
 * Es seguro usarlo desde varios hilos: cada firma crea su propia instancia de [Signature].
 */
public class Ed25519Signer private constructor(private val privateKey: PrivateKey) : Signer {
    override fun sign(signatureBase: ByteArray): ByteArray =
        Signature.getInstance(ALGORITHM).run {
            initSign(privateKey)
            update(signatureBase)
            sign()
        }

    override fun toString(): String = "Ed25519Signer"

    public companion object {
        private const val ALGORITHM = "Ed25519"
        private const val SEED_LENGTH = 32
        private const val PEM_HEADER = "-----BEGIN PRIVATE KEY-----"
        private const val PEM_FOOTER = "-----END PRIVATE KEY-----"

        // Cabecera DER de un PrivateKeyInfo PKCS#8 Ed25519 (RFC 8410 §7) seguida de la semilla.
        private val PKCS8_SEED_PREFIX = byteArrayOf(
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
            0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
        )

        /**
         * Carga la llave privada distinguiendo el formato por longitud: 32 bytes son la semilla
         * cruda; cualquier otra longitud se interpreta como texto PEM PKCS#8.
         *
         * @throws IllegalArgumentException si el material no es una llave Ed25519 válida.
         */
        public fun load(keyMaterial: ByteArray): Ed25519Signer =
            if (keyMaterial.size == SEED_LENGTH) fromSeed(keyMaterial) else fromPem(keyMaterial.decodeToString())

        /**
         * Carga una llave privada PKCS#8 en PEM (`-----BEGIN PRIVATE KEY-----`).
         *
         * @throws IllegalArgumentException si el PEM no contiene una llave Ed25519 PKCS#8.
         */
        public fun fromPem(pem: String): Ed25519Signer {
            val trimmed = pem.trim()
            require(trimmed.startsWith(PEM_HEADER) && trimmed.endsWith(PEM_FOOTER)) {
                "Se esperaba una llave PKCS#8 en PEM ($PEM_HEADER)"
            }
            val base64 = trimmed.removePrefix(PEM_HEADER).removeSuffix(PEM_FOOTER).filterNot { it.isWhitespace() }
            val der = try {
                Base64.decode(base64)
            } catch (e: IllegalArgumentException) {
                throw IllegalArgumentException("El contenido PEM no es base64 válido", e)
            }
            return fromPkcs8(der)
        }

        /**
         * Carga una llave privada a partir de la semilla cruda de 32 bytes (RFC 8032 §5.1.5).
         *
         * @throws IllegalArgumentException si la semilla no mide 32 bytes.
         */
        public fun fromSeed(seed: ByteArray): Ed25519Signer {
            require(seed.size == SEED_LENGTH) { "La semilla Ed25519 debe medir $SEED_LENGTH bytes, no ${seed.size}" }
            return fromPkcs8(PKCS8_SEED_PREFIX + seed)
        }

        /**
         * Usa una [PrivateKey] ya cargada.
         *
         * @throws IllegalArgumentException si la llave no es Ed25519.
         */
        public fun fromPrivateKey(privateKey: PrivateKey): Ed25519Signer {
            require((privateKey as? EdECPrivateKey)?.params?.name.equals(ALGORITHM, ignoreCase = true)) {
                "La llave privada no es Ed25519 (algoritmo ${privateKey.algorithm})"
            }
            return Ed25519Signer(privateKey)
        }

        private fun fromPkcs8(der: ByteArray): Ed25519Signer {
            val key = try {
                KeyFactory.getInstance(ALGORITHM).generatePrivate(PKCS8EncodedKeySpec(der))
            } catch (e: GeneralSecurityException) {
                throw IllegalArgumentException("El material no es una llave privada Ed25519 PKCS#8 válida", e)
            }
            return fromPrivateKey(key)
        }
    }
}
