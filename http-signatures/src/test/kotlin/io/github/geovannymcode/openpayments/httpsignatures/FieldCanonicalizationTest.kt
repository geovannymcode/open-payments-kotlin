package io.github.geovannymcode.openpayments.httpsignatures

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Canonicalización de campos de RFC 9421 §2.1, con los ejemplos de esa sección. */
class FieldCanonicalizationTest {
    private val request = HttpRequest(
        method = "GET",
        uri = "https://example.com/",
        headers = HttpHeaders.of(
            "X-OWS-Header" to "   Leading and trailing whitespace.   ",
            "X-Obs-Fold-Header" to "Obsolete\r\n    line folding.",
            "Cache-Control" to "max-age=60",
            "Cache-Control" to "   must-revalidate",
            "Example-Dict" to " a=1,    b=2;x=1;y=2,   c=(a   b   c)",
            "X-Empty-Header" to "",
        ),
    )

    private fun line(fieldName: String, target: HttpRequest = request): String =
        SignatureBase.of(target, listOf(Component.Field(fieldName)), SignatureParameters()).value.lines().first()

    @Test
    fun should_trim_leading_and_trailing_whitespace() {
        assertEquals("\"x-ows-header\": Leading and trailing whitespace.", line("x-ows-header"))
    }

    @Test
    fun should_replace_obsolete_line_folding_with_a_single_space() {
        assertEquals("\"x-obs-fold-header\": Obsolete line folding.", line("x-obs-fold-header"))
    }

    @Test
    fun should_join_repeated_fields_with_comma_and_space() {
        assertEquals("\"cache-control\": max-age=60, must-revalidate", line("cache-control"))
    }

    @Test
    fun should_keep_inner_whitespace_untouched() {
        assertEquals("\"example-dict\": a=1,    b=2;x=1;y=2,   c=(a   b   c)", line("example-dict"))
    }

    @Test
    fun should_serialize_empty_field_with_trailing_space() {
        assertEquals("\"x-empty-header\": ", line("x-empty-header"))
    }

    @Test
    fun should_match_field_names_case_insensitively() {
        assertEquals("\"cache-control\": max-age=60, must-revalidate", line("Cache-Control"))
    }

    @Test
    fun should_reject_missing_field() {
        assertFailsWith<IllegalArgumentException> { line("x-missing") }
    }

    @Test
    fun should_reject_covered_field_with_non_ascii_characters() {
        val accented = HttpRequest("GET", "https://example.com/", HttpHeaders.of("X-Description" to "Café en Barranquilla"))

        val error = assertFailsWith<IllegalArgumentException> {
            SignatureBase.of(accented, listOf(Component.Field("x-description")), SignatureParameters())
        }
        assertTrue("x-description" in error.message.orEmpty())
        assertTrue(";bs" in error.message.orEmpty())
    }

    @Test
    fun should_ignore_non_ascii_fields_that_are_not_covered() {
        val accented = request.withHeader("X-Description", "Café")

        assertEquals("\"x-ows-header\": Leading and trailing whitespace.", line("x-ows-header", accented))
    }

    @Test
    fun should_reject_bare_newline_that_is_not_obs_fold() {
        val broken = HttpRequest("GET", "https://example.com/", HttpHeaders.of("X-Broken" to "a\nb"))

        assertFailsWith<IllegalArgumentException> {
            SignatureBase.of(broken, listOf(Component.Field("x-broken")), SignatureParameters())
        }
    }
}
