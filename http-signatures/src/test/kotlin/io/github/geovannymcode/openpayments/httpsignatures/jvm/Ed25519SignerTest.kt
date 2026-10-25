package io.github.geovannymcode.openpayments.httpsignatures.jvm

import java.security.KeyPairGenerator
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull

class Ed25519SignerTest {
    @Test
    fun should_reject_seed_with_wrong_length() {
        assertFailsWith<IllegalArgumentException> { Ed25519Signer.fromSeed(ByteArray(31)) }
    }

    @Test
    fun should_reject_pem_that_is_not_pkcs8() {
        val openSsh = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"

        assertFailsWith<IllegalArgumentException> { Ed25519Signer.fromPem(openSsh) }
    }

    @Test
    fun should_reject_pem_with_invalid_base64() {
        val pem = "-----BEGIN PRIVATE KEY-----\n***\n-----END PRIVATE KEY-----"

        assertFailsWith<IllegalArgumentException> { Ed25519Signer.fromPem(pem) }
    }

    /**
     * El decodificador base64 de Kotlin cita en su mensaje símbolos válidos de la entrada (por
     * ejemplo, el que sigue a un relleno prematuro). Con una llave privada eso filtraría fragmentos.
     */
    @Test
    fun should_not_reveal_key_fragments_when_base64_is_malformed() {
        val malformedBodies = listOf(
            "MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqV==Tm50DFtMDoQikTmiCqirVv9mWG9qfSnF",
            "MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCq*rVv9mWG9qfSnF",
            "MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSn",
        )

        malformedBodies.forEach { body ->
            val error = assertFailsWith<IllegalArgumentException> {
                Ed25519Signer.fromPem("-----BEGIN PRIVATE KEY-----\n$body\n-----END PRIVATE KEY-----")
            }
            assertEquals("El contenido PEM no es base64 válido", error.message)
            assertNull(error.cause, "La causa original cita la entrada y no debe propagarse")
            assertFalse(error.stackTraceToString().contains(body.substring(20, 32)), "La traza no debe contener la llave")
        }
    }

    @Test
    fun should_reject_pkcs8_key_of_another_algorithm() {
        val ed448 = KeyPairGenerator.getInstance("Ed448").generateKeyPair().private
        val rsa = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair().private

        assertFailsWith<IllegalArgumentException> { Ed25519Signer.fromPrivateKey(ed448) }
        assertFailsWith<IllegalArgumentException> { Ed25519Signer.fromPem(Ed25519TestKeys.toPem("PRIVATE KEY", rsa.encoded)) }
    }

    @Test
    fun should_treat_non_seed_lengths_as_pem_text() {
        assertFailsWith<IllegalArgumentException> { Ed25519Signer.load(ByteArray(48)) }
    }
}
