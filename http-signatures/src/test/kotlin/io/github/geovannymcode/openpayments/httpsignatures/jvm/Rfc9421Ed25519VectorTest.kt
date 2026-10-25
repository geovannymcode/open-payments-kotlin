package io.github.geovannymcode.openpayments.httpsignatures.jvm

import io.github.geovannymcode.openpayments.httpsignatures.Component
import io.github.geovannymcode.openpayments.httpsignatures.ContentDigest
import io.github.geovannymcode.openpayments.httpsignatures.DigestAlgorithm
import io.github.geovannymcode.openpayments.httpsignatures.HttpHeaders
import io.github.geovannymcode.openpayments.httpsignatures.HttpMessageSigner
import io.github.geovannymcode.openpayments.httpsignatures.HttpRequest
import io.github.geovannymcode.openpayments.httpsignatures.HttpSignature
import io.github.geovannymcode.openpayments.httpsignatures.SignatureParameters
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Vector oficial de RFC 9421 apéndice B.2.6 (Ed25519), con la llave de B.1.4. */
class Rfc9421Ed25519VectorTest {
    private val privateKeyPem = """
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
        -----END PRIVATE KEY-----
    """.trimIndent()

    private val publicKeyPem = """
        -----BEGIN PUBLIC KEY-----
        MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
        -----END PUBLIC KEY-----
    """.trimIndent()

    private val body = """{"hello": "world"}""".encodeToByteArray()

    private val request = HttpRequest(
        method = "POST",
        uri = "https://example.com/foo?param=Value&Pet=dog",
        headers = HttpHeaders.of(
            "Host" to "example.com",
            "Date" to "Tue, 20 Apr 2021 02:07:55 GMT",
            "Content-Type" to "application/json",
            "Content-Length" to "18",
        ),
        body = body,
    )

    private val components = listOf(
        Component.Field("date"),
        Component.Method,
        Component.Path,
        Component.Authority,
        Component.Field("content-type"),
        Component.Field("content-length"),
    )

    private val parameters = SignatureParameters(created = 1618884473, keyId = "test-key-ed25519")

    private val expectedSignatureBase = listOf(
        "\"date\": Tue, 20 Apr 2021 02:07:55 GMT",
        "\"@method\": POST",
        "\"@path\": /foo",
        "\"@authority\": example.com",
        "\"content-type\": application/json",
        "\"content-length\": 18",
        "\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\")" +
            ";created=1618884473;keyid=\"test-key-ed25519\"",
    ).joinToString("\n")

    private val expectedSignature =
        "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw=="

    private fun sign(): HttpSignature =
        HttpMessageSigner(Ed25519Signer.fromPem(privateKeyPem)).sign(request, components, parameters, label = "sig-b26")

    @Test
    fun should_have_an_18_byte_body() {
        assertEquals(18, body.size)
    }

    @Test
    fun should_compute_sha_512_content_digest_of_test_body() {
        assertEquals(
            "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
            ContentDigest.headerValue(body, listOf(DigestAlgorithm.SHA_512)),
        )
    }

    @Test
    fun should_compute_sha_256_content_digest_of_test_body() {
        assertEquals(
            "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
            ContentDigest.headerValue(body, listOf(DigestAlgorithm.SHA_256)),
        )
    }

    @Test
    fun should_build_the_exact_signature_base_of_b_2_6() {
        assertEquals(expectedSignatureBase, sign().signatureBase.value)
    }

    @Test
    fun should_not_end_signature_base_with_a_newline() {
        val base = sign().signatureBase.value

        assertFalse(base.endsWith("\n"), "La signature base no debe terminar en salto de línea")
        assertFalse(base.endsWith("\r"), "La signature base no debe terminar en retorno de carro")
        assertTrue(base.endsWith(";keyid=\"test-key-ed25519\""))
    }

    @Test
    fun should_omit_alg_parameter_by_default() {
        assertFalse(";alg=" in sign().signatureBase.signatureParams)
    }

    @Test
    fun should_produce_the_exact_signature_of_b_2_6() {
        assertEquals(expectedSignature, Base64.encode(sign().signature))
    }

    @Test
    fun should_verify_the_official_signature_with_the_published_public_key() {
        assertTrue(Ed25519TestKeys.verify(publicKeyPem, expectedSignatureBase.encodeToByteArray(), Base64.decode(expectedSignature)))
    }

    @Test
    fun should_serialize_signature_input_and_signature_fields() {
        val signature = sign()

        assertEquals(
            "sig-b26=(\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\")" +
                ";created=1618884473;keyid=\"test-key-ed25519\"",
            signature.signatureInput,
        )
        assertEquals("sig-b26=:$expectedSignature:", signature.signatureHeader)

        val signed = signature.applyTo(request)
        assertEquals(listOf(signature.signatureInput), signed.headers.values("signature-input"))
        assertEquals(listOf(signature.signatureHeader), signed.headers.values("signature"))
    }

    @Test
    fun should_sign_identically_from_pem_raw_seed_and_load() {
        val seed = Ed25519TestKeys.pemBody(privateKeyPem).takeLast(32).toByteArray()
        val fromSeed = Ed25519Signer.fromSeed(seed).sign(expectedSignatureBase.encodeToByteArray())
        val fromLoadedSeed = Ed25519Signer.load(seed).sign(expectedSignatureBase.encodeToByteArray())
        val fromLoadedPem = Ed25519Signer.load(privateKeyPem.encodeToByteArray()).sign(expectedSignatureBase.encodeToByteArray())

        val expected = Base64.decode(expectedSignature)
        assertContentEquals(expected, fromSeed)
        assertContentEquals(expected, fromLoadedSeed)
        assertContentEquals(expected, fromLoadedPem)
    }
}
