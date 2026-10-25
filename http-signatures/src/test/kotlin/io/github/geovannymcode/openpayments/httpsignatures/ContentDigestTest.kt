package io.github.geovannymcode.openpayments.httpsignatures

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ContentDigestTest {
    private val body = """{"hello": "world"}""".encodeToByteArray()

    @Test
    fun should_use_sha_512_by_default() {
        assertEquals(
            "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
            ContentDigest.headerValue(body),
        )
    }

    @Test
    fun should_serialize_several_algorithms_as_dictionary_in_order() {
        assertEquals(
            "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:, " +
                "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
            ContentDigest.headerValue(body, listOf(DigestAlgorithm.SHA_256, DigestAlgorithm.SHA_512)),
        )
    }

    @Test
    fun should_replace_existing_content_digest_on_request() {
        val request = HttpRequest(
            method = "POST",
            uri = "https://example.com/",
            headers = HttpHeaders.of("Content-Digest" to "sha-256=:stale:"),
            body = body,
        ).withContentDigest(listOf(DigestAlgorithm.SHA_256))

        assertEquals(listOf("sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"), request.headers.values("content-digest"))
    }

    @Test
    fun should_reject_request_without_body() {
        assertFailsWith<IllegalArgumentException> { HttpRequest("GET", "https://example.com/").withContentDigest() }
    }

    @Test
    fun should_reject_empty_algorithm_list() {
        assertFailsWith<IllegalArgumentException> { ContentDigest.headerValue(body, emptyList()) }
    }
}
