package io.github.geovannymcode.openpayments.httpsignatures.jvm

import java.security.KeyPairGenerator
import kotlin.test.Test
import kotlin.test.assertFailsWith

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
