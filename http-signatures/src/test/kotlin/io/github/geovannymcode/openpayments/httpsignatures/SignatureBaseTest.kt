package io.github.geovannymcode.openpayments.httpsignatures

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class SignatureBaseTest {
    private val request = HttpRequest("GET", "https://example.com/", HttpHeaders.of("Date" to "x"))

    @Test
    fun should_serialize_parameters_in_canonical_order() {
        val parameters = SignatureParameters(
            created = 1,
            expires = 2,
            nonce = "n",
            algorithm = "ed25519",
            keyId = "k",
            tag = "t",
        )

        assertEquals(
            "(\"@method\");created=1;expires=2;nonce=\"n\";alg=\"ed25519\";keyid=\"k\";tag=\"t\"",
            SignatureBase.of(request, listOf(Component.Method), parameters).signatureParams,
        )
    }

    @Test
    fun should_serialize_empty_component_list() {
        val base = SignatureBase.of(request, emptyList(), SignatureParameters(created = 1))

        assertEquals("\"@signature-params\": ();created=1", base.value)
    }

    @Test
    fun should_encode_signature_base_as_us_ascii() {
        val base = SignatureBase.of(request, listOf(Component.Field("date")), SignatureParameters(created = 1))

        assertContentEquals(base.value.map { it.code.toByte() }.toByteArray(), base.toByteArray())
    }

    @Test
    fun should_reject_duplicate_components() {
        assertFailsWith<IllegalArgumentException> {
            SignatureBase.of(request, listOf(Component.Field("Date"), Component.Field("date")), SignatureParameters())
        }
    }

    @Test
    fun should_escape_quotes_and_backslashes_in_string_parameters() {
        val base = SignatureBase.of(request, emptyList(), SignatureParameters(keyId = "a\"b\\c"))

        assertEquals("();keyid=\"a\\\"b\\\\c\"", base.signatureParams)
    }

    @Test
    fun should_reject_non_ascii_string_parameters() {
        assertFailsWith<IllegalArgumentException> {
            SignatureBase.of(request, emptyList(), SignatureParameters(keyId = "llave-ñ"))
        }
    }

    @Test
    fun should_reject_integers_longer_than_15_digits() {
        assertFailsWith<IllegalArgumentException> {
            SignatureBase.of(request, emptyList(), SignatureParameters(created = 1_000_000_000_000_000))
        }
    }

    @Test
    fun should_reject_invalid_signature_label() {
        val signer = HttpMessageSigner { ByteArray(0) }

        assertFailsWith<IllegalArgumentException> { signer.sign(request, emptyList(), SignatureParameters(), label = "Sig1") }
    }

    @Test
    fun should_reject_field_component_named_like_a_derived_component() {
        assertFailsWith<IllegalArgumentException> { Component.Field("@method") }
    }
}
