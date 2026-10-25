package io.github.geovannymcode.openpayments.httpsignatures.jvm

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import kotlin.io.encoding.Base64

/** Utilidades de prueba para generar llaves y verificar firmas Ed25519 con el JDK. */
internal object Ed25519TestKeys {
    fun generate(): KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

    fun toPem(label: String, der: ByteArray): String =
        "-----BEGIN $label-----\n" + Base64.Mime.encode(der) + "\n-----END $label-----\n"

    fun pemBody(pem: String): List<Byte> =
        Base64.decode(pem.lines().filterNot { it.startsWith("-----") }.joinToString("")).toList()

    fun verify(publicKey: PublicKey, data: ByteArray, signature: ByteArray): Boolean =
        Signature.getInstance("Ed25519").run {
            initVerify(publicKey)
            update(data)
            verify(signature)
        }

    fun verify(publicKeyPem: String, data: ByteArray, signature: ByteArray): Boolean {
        val publicKey = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(pemBody(publicKeyPem).toByteArray()))
        return verify(publicKey, data, signature)
    }
}
