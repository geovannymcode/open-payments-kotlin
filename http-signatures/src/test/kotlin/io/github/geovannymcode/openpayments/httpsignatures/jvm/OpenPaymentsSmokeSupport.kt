package io.github.geovannymcode.openpayments.httpsignatures.jvm

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.net.URI
import java.net.URISyntaxException
import java.net.http.HttpClient
import java.time.Duration
import java.net.http.HttpRequest as JdkHttpRequest

/**
 * Lógica del smoke test de Open Payments que no necesita red, separada para poder probarla con
 * tests unitarios deterministas.
 *
 * Ningún mensaje que se genera aquí incluye el cuerpo de la respuesta ni el access token: solo el
 * código HTTP, códigos de error saneados y qué condición falló.
 */
internal object OpenPaymentsSmoke {
    /** Timeout de cada petición HTTP del smoke test: descubrimiento de la wallet, JWKS y grant. */
    val REQUEST_TIMEOUT: Duration = Duration.ofSeconds(30)

    /** Acciones que se piden para `incoming-payment` y que el grant aprobado debe conceder. */
    val INCOMING_PAYMENT_ACTIONS: List<String> = listOf("create", "read", "list")

    private val ERROR_CODE = Regex("[a-z_]{1,64}")

    /** Base64 DER header shared by every PKCS#8 Ed25519 private key (RFC 8410), not secret by itself. */
    private const val PKCS8_ED25519_BASE64_PREFIX = "MC4CAQAwBQYDK2VwBCIEI"

    /**
     * Detects values that are explicitly private key material: a PEM private key block or a
     * Base64-encoded PKCS#8 Ed25519 key.
     *
     * It deliberately does not judge by decoded Base64 length: a legitimate `kid` can be valid
     * Base64 of any size. Whether the `kid` is published and matches the private key is checked
     * against the JWKS by the integration test's key registration preflight.
     */
    fun looksLikeKeyMaterial(value: String): Boolean =
        "PRIVATE KEY" in value || value.trim().startsWith(PKCS8_ED25519_BASE64_PREFIX)

    /** Connection timeout of the smoke test HTTP client. */
    val CONNECT_TIMEOUT: Duration = Duration.ofSeconds(15)

    /**
     * Builds the HTTP client used by the smoke test.
     *
     * Redirects are never followed, explicitly rather than relying on the JDK default: a 3xx from
     * the wallet address, the JWKS or the auth server could send the signed request, and later the
     * access token, to plain HTTP. A 3xx is returned as is and fails the test like any other
     * non-200 status. HTTP/1.1 guarantees that the JDK sends Content-Length, a covered component.
     */
    fun newHttpClient(): HttpClient =
        HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(CONNECT_TIMEOUT)
            .build()

    /**
     * Normalizes and validates a wallet address before any request is sent to it.
     *
     * A payment pointer (`$wallet.example/alice`) becomes `https://wallet.example/alice`. The result
     * must be an absolute `https` URL with a valid host and without user info, explicit port, query
     * or fragment, which is the form Open Payments wallet addresses take.
     *
     * @throws IllegalArgumentException if the address does not meet those rules. The message never
     * echoes the value, since its user info could embed credentials.
     */
    fun normalizeWalletAddress(walletAddress: String): String {
        val trimmed = walletAddress.trim()
        val candidate = if (trimmed.startsWith("$")) "https://${trimmed.substring(1)}" else trimmed
        val uri = parseHttpsUri(candidate, label = "Wallet address")
        require(uri.rawUserInfo == null) { "Wallet address must not contain user info" }
        require(uri.port == -1) { "Wallet address must not contain an explicit port" }
        require(uri.rawQuery == null) { "Wallet address must not contain a query" }
        require(uri.rawFragment == null) { "Wallet address must not contain a fragment" }
        return candidate
    }

    /**
     * Validates the `authServer` published by a wallet address before a signed request is sent to it.
     *
     * It must be an absolute `https` URI with a valid host and without embedded credentials. Path
     * and query are kept untouched, since the auth server may need them (for example a tenant path).
     *
     * @throws IllegalArgumentException if the URI does not meet those rules; the value is not echoed.
     */
    fun requireHttpsAuthServer(authServer: String): String {
        val uri = parseHttpsUri(authServer, label = "authServer")
        require(uri.rawUserInfo == null) { "authServer must not contain embedded credentials" }
        return authServer
    }

    /** Parses [value] with [URI] and requires an absolute `https` URI with a non-blank host. */
    private fun parseHttpsUri(value: String, label: String): URI {
        val uri = try {
            URI(value)
        } catch (_: URISyntaxException) {
            throw IllegalArgumentException("$label is not a valid URI")
        }
        require(uri.isAbsolute && uri.scheme.equals("https", ignoreCase = true)) { "$label must use https" }
        require(!uri.host.isNullOrBlank()) { "$label must have a valid host" }
        return uri
    }

    /**
     * Construye un GET de descubrimiento (wallet address o su JWKS), con [REQUEST_TIMEOUT] explícito
     * para que un servidor que no responde no deje el test colgado.
     */
    fun discoveryRequest(url: String): JdkHttpRequest =
        JdkHttpRequest.newBuilder(URI.create(url))
            .timeout(REQUEST_TIMEOUT)
            .header("Accept", "application/json")
            .GET()
            .build()

    /**
     * Cuerpo GNAP de una solicitud de grant de `incoming-payment` sin interacción, en la forma de la
     * spec del auth server de Open Payments.
     *
     * @param client wallet address del cliente, que publica en su JWKS la llave que firma.
     */
    fun incomingPaymentGrantBody(client: String): ByteArray {
        val actions = INCOMING_PAYMENT_ACTIONS.joinToString(",") { "\"$it\"" }
        return """{"access_token":{"access":[{"type":"incoming-payment","actions":[$actions]}]},"client":"$client"}"""
            .encodeToByteArray()
    }

    /**
     * Interpreta [body] como JSON, o devuelve `null` si no lo es.
     *
     * Usa `Json.parseToJsonElement` tal cual. Dos comportamientos verificados de la 1.11.0 que el
     * resto del código tiene en cuenta: con claves duplicadas gana la última, igual que `JSON.parse`
     * en el SDK oficial de TypeScript, así que ambos interpretan la misma respuesta igual; y acepta
     * literales sin comillas, por eso los campos de texto se leen con [stringField], que exige
     * `isString`. Un anidamiento extremo lanza `StackOverflowError`, que hace fallar el test.
     */
    fun parseJson(body: String): JsonElement? =
        try {
            Json.parseToJsonElement(body)
        } catch (_: SerializationException) {
            null
        }

    /**
     * Evalúa la respuesta a una solicitud de grant de `incoming-payment`.
     *
     * Solo cuenta como éxito un `200` con un grant aprobado y finalizado, el mismo criterio que
     * `isFinalizedGrantWithAccessToken` del SDK oficial: sin `interact`, con `access_token.value`,
     * `access_token.manage` y un `access_token.access` que concede `incoming-payment` con todas las
     * acciones pedidas. Cualquier otro estado, incluido un `400`, es un fallo: no demuestra que el
     * servidor haya validado la firma.
     *
     * @return `null` si el grant es válido; si no, el motivo saneado del fallo.
     */
    fun grantFailure(status: Int, body: String): String? {
        val json = parseJson(body)
        if (status != 200) {
            val code = sanitizedErrorCode(json)
            return if (status == 401 || status == 403) {
                "El servidor rechazó la firma o el cliente ($status, código de error: $code)"
            } else {
                "Se esperaba 200 y el servidor respondió $status (código de error: $code)"
            }
        }
        val root = json as? JsonObject ?: return "200 con un cuerpo que no es un objeto JSON"
        if ("interact" in root) return "200 con interacción pendiente: el grant no está finalizado"
        val accessToken = root["access_token"] as? JsonObject ?: return "200 sin access_token"
        if (accessToken.stringField("value").isNullOrBlank()) return "200 con access_token.value ausente o vacío"
        if (accessToken.stringField("manage").isNullOrBlank()) return "200 con access_token.manage ausente o vacío"
        val access = accessToken["access"] as? JsonArray ?: return "200 sin access_token.access"
        val incomingPayment = access.filterIsInstance<JsonObject>().firstOrNull { it.stringField("type") == "incoming-payment" }
            ?: return "200 con un grant que no concede incoming-payment"
        val grantedActions = (incomingPayment["actions"] as? JsonArray).orEmpty()
            .mapNotNull { (it as? JsonPrimitive)?.takeIf(JsonPrimitive::isString)?.content }
        val missingActions = INCOMING_PAYMENT_ACTIONS.filterNot { it in grantedActions }
        if (missingActions.isNotEmpty()) return "200 con un grant de incoming-payment sin las acciones $missingActions"
        return null
    }

    /** Valor de texto de [key], o `null` si falta o no es una cadena JSON entre comillas. */
    fun JsonObject.stringField(key: String): String? =
        (this[key] as? JsonPrimitive)?.takeIf(JsonPrimitive::isString)?.content

    /** Código GNAP de `error.code`, solo si tiene forma de código; nunca texto libre del servidor. */
    private fun sanitizedErrorCode(json: JsonElement?): String {
        val code = ((json as? JsonObject)?.get("error") as? JsonObject)?.stringField("code")
        return code?.takeIf { ERROR_CODE.matches(it) } ?: "desconocido"
    }
}
