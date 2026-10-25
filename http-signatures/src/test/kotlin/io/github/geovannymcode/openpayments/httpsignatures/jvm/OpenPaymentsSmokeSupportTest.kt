package io.github.geovannymcode.openpayments.httpsignatures.jvm

import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Criterios del smoke test de Open Payments, verificados sin red. */
class OpenPaymentsSmokeSupportTest {
    private val token = "OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0"

    private val approvedGrant = """
        {
          "access_token": {
            "value": "$token",
            "manage": "https://auth.example/token/dd17a202",
            "expires_in": 600,
            "access": [{"type": "incoming-payment", "actions": ["create", "read", "list"]}]
          },
          "continue": {"access_token": {"value": "33OMUKMKSKU80UPRY5NM"}, "uri": "https://auth.example/continue/4CF4"}
        }
    """.trimIndent()

    /** Forma del ejemplo «Grant» de la spec del auth server (v1.4.0): token, `manage`, `access` y `continue`. */
    @Test
    fun should_accept_approved_grant_with_access_token() {
        assertNull(OpenPaymentsSmoke.grantFailure(200, approvedGrant))
    }

    /** Un 400 no prueba que la firma se validó: Rafiki puede rechazar la petición antes de verificarla. */
    @Test
    fun should_fail_on_400_even_with_invalid_request() {
        val failure = OpenPaymentsSmoke.grantFailure(400, """{"error":{"code":"invalid_request","description":"x"}}""")

        assertEquals("Se esperaba 200 y el servidor respondió 400 (código de error: invalid_request)", failure)
    }

    /** Rechazo de firma o de cliente: se reporta el código GNAP, nunca la descripción libre del servidor. */
    @Test
    fun should_fail_on_401_and_403() {
        val body = """{"error":{"code":"invalid_client","description":"invalid signature"}}"""

        assertEquals("El servidor rechazó la firma o el cliente (401, código de error: invalid_client)", OpenPaymentsSmoke.grantFailure(401, body))
        assertNotNull(OpenPaymentsSmoke.grantFailure(403, body))
    }

    /** Ejemplo «Interaction instructions» de la spec: es un 200, pero el grant no está finalizado. */
    @Test
    fun should_fail_on_pending_interaction_grant() {
        val pending = """
            {"interact":{"redirect":"https://auth.example/4CF4","finish":"4105340a"},
             "continue":{"access_token":{"value":"33OM"},"uri":"https://auth.example/continue/4CF4","wait":30}}
        """.trimIndent()

        assertEquals("200 con interacción pendiente: el grant no está finalizado", OpenPaymentsSmoke.grantFailure(200, pending))
    }

    /** Un 200 con solo `continue` no entrega acceso: `isFinalizedGrantWithAccessToken` lo rechaza. */
    @Test
    fun should_fail_on_200_without_access_token() {
        assertEquals("200 sin access_token", OpenPaymentsSmoke.grantFailure(200, """{"continue":{"uri":"https://auth.example/c"}}"""))
    }

    /** `value` y `manage` son obligatorios en el esquema `access_token` de la spec. */
    @Test
    fun should_fail_on_200_with_blank_token_value_or_missing_manage() {
        val blankValue = approvedGrant.replace("\"$token\"", "\"  \"")
        val noManage = approvedGrant.replace("\"manage\": \"https://auth.example/token/dd17a202\",", "")

        assertEquals("200 con access_token.value ausente o vacío", OpenPaymentsSmoke.grantFailure(200, blankValue))
        assertEquals("200 con access_token.manage ausente o vacío", OpenPaymentsSmoke.grantFailure(200, noManage))
    }

    /** El grant debe conceder lo que pidió el test, no un acceso distinto o reducido. */
    @Test
    fun should_fail_when_grant_does_not_cover_incoming_payment_or_requested_actions() {
        val otherType = approvedGrant.replace("\"incoming-payment\"", "\"quote\"")
        val fewerActions = approvedGrant.replace("[\"create\", \"read\", \"list\"]", "[\"read\"]")

        assertEquals("200 con un grant que no concede incoming-payment", OpenPaymentsSmoke.grantFailure(200, otherType))
        assertEquals("200 con un grant de incoming-payment sin las acciones [create, list]", OpenPaymentsSmoke.grantFailure(200, fewerActions))
    }

    /** Una página HTML de un proxy o portal cautivo con 200 no es un grant. */
    @Test
    fun should_fail_on_200_with_non_json_body() {
        assertEquals("200 con un cuerpo que no es un objeto JSON", OpenPaymentsSmoke.grantFailure(200, "<html>ok</html>"))
    }

    /** Los mensajes de fallo terminan en logs de CI: no pueden contener el token ni texto del servidor. */
    @Test
    fun should_never_include_token_or_free_text_in_failure_messages() {
        val failures = listOf(
            OpenPaymentsSmoke.grantFailure(200, approvedGrant.replace("\"incoming-payment\"", "\"quote\"")),
            OpenPaymentsSmoke.grantFailure(500, """{"error":{"code":"Token $token leaked","description":"$token"}}"""),
        )

        failures.forEach { assertFalse(token in it.orEmpty(), "El mensaje no debe contener el token") }
        assertEquals("Se esperaba 200 y el servidor respondió 500 (código de error: desconocido)", failures[1])
    }

    /** Sin timeout, una wallet address que no responde deja colgado el test y el job de CI. */
    @Test
    fun should_set_explicit_timeout_on_discovery_request() {
        val request = OpenPaymentsSmoke.discoveryRequest("https://ilp.example/alice")

        assertEquals(OpenPaymentsSmoke.REQUEST_TIMEOUT, request.timeout().orElse(null))
        assertEquals("GET", request.method())
    }

    /** Ejemplo «Grant request for creating and reading incoming payments» de la spec, con `list`. */
    @Test
    fun should_build_grant_body_in_spec_shape() {
        val body = Json.parseToJsonElement(OpenPaymentsSmoke.incomingPaymentGrantBody("https://ilp.example/alice").decodeToString())
        val expected = """
            {"access_token": {"access": [{"type": "incoming-payment", "actions": ["create", "read", "list"]}]},
             "client": "https://ilp.example/alice"}
        """.trimIndent()

        assertEquals(Json.parseToJsonElement(expected), body)
    }

    /**
     * Campos presentes pero con el tipo JSON equivocado no deben pasar por un grant válido. Incluye
     * literales sin comillas, que `Json.parseToJsonElement` acepta pero no son cadenas JSON.
     */
    @Test
    fun should_fail_when_grant_fields_have_wrong_json_types() {
        val cases = mapOf(
            "valor numérico" to approvedGrant.replace("\"$token\"", "12345"),
            "valor sin comillas" to approvedGrant.replace("\"$token\"", token),
            "tipo sin comillas" to approvedGrant.replace("\"incoming-payment\"", "incoming-payment"),
            "acciones sin comillas" to approvedGrant.replace("[\"create\", \"read\", \"list\"]", "[create, read, list]"),
            "access_token como arreglo" to """{"access_token":[{"value":"$token","manage":"https://a/t","access":[]}]}""",
            "access como objeto" to approvedGrant.replace(
                """[{"type": "incoming-payment", "actions": ["create", "read", "list"]}]""",
                """{"type": "incoming-payment", "actions": ["create", "read", "list"]}""",
            ),
            "acciones como texto" to approvedGrant.replace("[\"create\", \"read\", \"list\"]", "\"create read list\""),
            "interact nulo" to approvedGrant.replaceFirst("{", """{"interact": null,"""),
            "raíz como arreglo" to "[$approvedGrant]",
            "raíz como literal" to "<html>ok</html>",
        )

        cases.forEach { (case, body) -> assertNotNull(OpenPaymentsSmoke.grantFailure(200, body), "Debe fallar: $case") }
    }

    /** La spec solo define 200 para un grant aprobado; otro 2xx o una redirección es una respuesta inesperada. */
    @Test
    fun should_fail_on_valid_grant_body_with_status_other_than_200() {
        listOf(201, 202, 204, 302).forEach { status ->
            assertNotNull(OpenPaymentsSmoke.grantFailure(status, approvedGrant), "Debe fallar con $status")
        }
    }

    /** Una respuesta cortada por un proxy o una conexión interrumpida nunca valida un grant. */
    @Test
    fun should_fail_on_invalid_or_incomplete_json_responses() {
        val invalid = listOf(
            "",
            approvedGrant.dropLast(1),
            approvedGrant.substring(0, approvedGrant.length / 2),
            "$approvedGrant}",
            "$approvedGrant extra",
            approvedGrant.replace("\"expires_in\": 600,", "\"expires_in\": 600,,"),
            approvedGrant.replace("\"manage\":", "manage:"),
            approvedGrant.replace("\"value\": \"$token\"", "\"value\" \"$token\""),
            approvedGrant.replace("\"$token\"", "\"$token"),
            approvedGrant.replace("\"$token\"", "\"\\x$token\""),
        )

        invalid.forEach { body -> assertNotNull(OpenPaymentsSmoke.grantFailure(200, body), "Debe fallar: ${body.take(40)}") }
    }

    /**
     * Decisión documentada: `Json.parseToJsonElement` no rechaza claves duplicadas, gana la última,
     * igual que `JSON.parse` en el SDK oficial. Se fija ese comportamiento para que un cambio de la
     * biblioteca no altere el criterio sin que un test lo detecte.
     */
    @Test
    fun should_resolve_duplicated_keys_with_last_value_as_the_official_sdk_does() {
        val lastInvalid = approvedGrant.trimEnd().removeSuffix("}") + ""","access_token": {"value": ""}}"""
        val lastValid = approvedGrant.replaceFirst("{", """{"access_token": {"value": ""},""")

        assertEquals("200 con access_token.value ausente o vacío", OpenPaymentsSmoke.grantFailure(200, lastInvalid))
        assertNull(OpenPaymentsSmoke.grantFailure(200, lastValid))
    }

    /**
     * Un anidamiento hostil hace que `Json.parseToJsonElement` lance `StackOverflowError`. No se
     * captura un `Error` en el código de soporte: basta con que el resultado nunca sea un éxito.
     */
    @Test
    fun should_never_accept_deeply_nested_response() {
        val outcome = runCatching { OpenPaymentsSmoke.grantFailure(200, "[".repeat(10_000) + "]".repeat(10_000)) }

        assertTrue(outcome.isFailure || outcome.getOrNull() != null, "Un anidamiento extremo no puede validar un grant")
    }
}
