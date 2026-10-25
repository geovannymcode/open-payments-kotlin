package io.github.geovannymcode.openpayments.httpsignatures.jvm

import io.github.geovannymcode.openpayments.httpsignatures.Component
import io.github.geovannymcode.openpayments.httpsignatures.ContentDigest
import io.github.geovannymcode.openpayments.httpsignatures.HttpHeaders
import io.github.geovannymcode.openpayments.httpsignatures.HttpMessageSigner
import io.github.geovannymcode.openpayments.httpsignatures.HttpRequest
import io.github.geovannymcode.openpayments.httpsignatures.SignatureBase
import io.github.geovannymcode.openpayments.httpsignatures.SignatureParameters
import io.github.geovannymcode.openpayments.httpsignatures.withContentDigest
import java.security.KeyPair
import java.security.spec.PKCS8EncodedKeySpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Firma y verifica una petición con la forma de `POST /incoming-payments` de Open Payments. */
class OpenPaymentsRoundTripTest {
    private val keyPair: KeyPair = Ed25519TestKeys.generate()

    private val body = """
        {"walletAddress":"https://ilp.wallet.example/alice","incomingAmount":{"value":"2500","assetCode":"USD","assetScale":2},"metadata":{"description":"Café en Barranquilla"}}
    """.trim().encodeToByteArray()

    private val request = HttpRequest(
        method = "POST",
        uri = "https://auth.wallet.example/incoming-payments",
        headers = HttpHeaders.of(
            "Authorization" to "GNAP 4398DD3E7A4F4A5D8B8E",
            "Content-Type" to "application/json",
            "Content-Length" to body.size.toString(),
        ),
        body = body,
    ).withContentDigest()

    private val components = listOf(
        Component.Method,
        Component.TargetUri,
        Component.Field("authorization"),
        Component.Field("content-digest"),
        Component.Field("content-length"),
        Component.Field("content-type"),
    )

    private val parameters = SignatureParameters(created = 1_761_400_000, keyId = "op-test-key")

    private fun signer(): HttpMessageSigner {
        val pem = Ed25519TestKeys.toPem("PRIVATE KEY", keyPair.private.encoded)
        return HttpMessageSigner(Ed25519Signer.load(pem.encodeToByteArray()))
    }

    @Test
    fun should_sign_and_verify_an_incoming_payment_request() {
        val signature = signer().sign(request, components, parameters)

        val expectedBase = listOf(
            "\"@method\": POST",
            "\"@target-uri\": https://auth.wallet.example/incoming-payments",
            "\"authorization\": GNAP 4398DD3E7A4F4A5D8B8E",
            "\"content-digest\": ${ContentDigest.headerValue(body)}",
            "\"content-length\": ${body.size}",
            "\"content-type\": application/json",
            "\"@signature-params\": (\"@method\" \"@target-uri\" \"authorization\" \"content-digest\" " +
                "\"content-length\" \"content-type\");created=1761400000;keyid=\"op-test-key\"",
        ).joinToString("\n")

        assertEquals(expectedBase, signature.signatureBase.value)
        assertTrue(Ed25519TestKeys.verify(keyPair.public, signature.signatureBase.toByteArray(), signature.signature))
        assertTrue(signature.signatureInput.startsWith("sig1=("))
        assertTrue(signature.signatureHeader.startsWith("sig1=:"))
    }

    @Test
    fun should_fail_verification_when_a_covered_field_changes() {
        val signature = signer().sign(request, components, parameters)
        val tampered = request.replacingHeader("Authorization", "GNAP otro-token")
        val tamperedBase = SignatureBase.of(tampered, components, parameters)

        assertFalse(Ed25519TestKeys.verify(keyPair.public, tamperedBase.toByteArray(), signature.signature))
    }

    @Test
    fun should_sign_with_a_raw_seed_extracted_from_the_generated_key() {
        val pkcs8 = PKCS8EncodedKeySpec(keyPair.private.encoded).encoded
        val seed = pkcs8.copyOfRange(pkcs8.size - 32, pkcs8.size)
        val base = SignatureBase.of(request, components, parameters).toByteArray()

        assertTrue(Ed25519TestKeys.verify(keyPair.public, base, Ed25519Signer.load(seed).sign(base)))
    }

    @Test
    fun should_reject_signing_when_a_covered_field_is_missing() {
        val withoutAuthorization = HttpRequest(request.method, request.uri, HttpHeaders.of("Content-Type" to "application/json"))

        assertFailsWith<IllegalArgumentException> { signer().sign(withoutAuthorization, components, parameters) }
    }
}
