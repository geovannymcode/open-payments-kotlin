package io.github.geovannymcode.openpayments.httpsignatures

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class DerivedComponentsTest {
    private fun valueOf(component: Component, uri: String, method: String = "GET"): String {
        val base = SignatureBase.of(HttpRequest(method, uri), listOf(component), SignatureParameters())
        return base.value.lines().first().substringAfter(": ")
    }

    @Test
    fun should_use_method_as_sent() {
        assertEquals("POST", valueOf(Component.Method, "https://example.com/", method = "POST"))
    }

    @Test
    fun should_build_target_uri_without_fragment() {
        assertEquals(
            "https://www.example.com/path?param=value",
            valueOf(Component.TargetUri, "https://www.example.com/path?param=value#section"),
        )
    }

    @Test
    fun should_lowercase_authority_host() {
        assertEquals("www.example.com", valueOf(Component.Authority, "https://WWW.Example.COM/path"))
    }

    @Test
    fun should_omit_default_port_from_authority() {
        assertEquals("example.com", valueOf(Component.Authority, "https://example.com:443/"))
        assertEquals("example.com", valueOf(Component.Authority, "http://example.com:80/"))
    }

    @Test
    fun should_keep_non_default_port_in_authority() {
        assertEquals("example.com:8443", valueOf(Component.Authority, "https://example.com:8443/"))
        assertEquals("example.com:443", valueOf(Component.Authority, "http://example.com:443/"))
    }

    @Test
    fun should_strip_userinfo_and_keep_ipv6_literal_in_authority() {
        assertEquals("example.com", valueOf(Component.Authority, "https://user:pass@example.com/"))
        assertEquals("[::1]:8080", valueOf(Component.Authority, "http://[::1]:8080/"))
        assertEquals("[::1]", valueOf(Component.Authority, "https://[::1]:443/"))
    }

    @Test
    fun should_lowercase_scheme() {
        assertEquals("https", valueOf(Component.Scheme, "HTTPS://example.com/"))
    }

    @Test
    fun should_build_request_target_with_and_without_query() {
        assertEquals("/path?param=value", valueOf(Component.RequestTarget, "https://example.com/path?param=value"))
        assertEquals("/path", valueOf(Component.RequestTarget, "https://example.com/path"))
    }

    @Test
    fun should_return_slash_as_path_when_uri_has_no_path() {
        assertEquals("/", valueOf(Component.Path, "https://example.com"))
        assertEquals("/", valueOf(Component.Path, "https://example.com?a=b"))
        assertEquals("/foo", valueOf(Component.Path, "https://example.com/foo?param=Value&Pet=dog"))
    }

    @Test
    fun should_keep_percent_encoding_in_path_and_query() {
        assertEquals("/a%2Fb", valueOf(Component.Path, "https://example.com/a%2Fb"))
        assertEquals("?param=value&foo=bar&baz=bat%2Dman", valueOf(Component.Query, "https://example.com/?param=value&foo=bar&baz=bat%2Dman"))
    }

    @Test
    fun should_return_question_mark_alone_when_there_is_no_query() {
        assertEquals("?", valueOf(Component.Query, "https://example.com/path"))
        assertEquals("?param=Value&Pet=dog", valueOf(Component.Query, "https://example.com/foo?param=Value&Pet=dog"))
    }

    @Test
    fun should_reject_relative_uri() {
        assertFailsWith<IllegalArgumentException> { HttpRequest("GET", "/incoming-payments") }
        assertFailsWith<IllegalArgumentException> { HttpRequest("GET", "https:///path") }
        assertFailsWith<IllegalArgumentException> { HttpRequest("GET", "https://example.com:abc/") }
    }
}
