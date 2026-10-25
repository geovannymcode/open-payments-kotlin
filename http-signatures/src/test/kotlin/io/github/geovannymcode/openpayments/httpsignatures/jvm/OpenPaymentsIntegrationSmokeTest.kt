package io.github.geovannymcode.openpayments.httpsignatures.jvm

import io.github.geovannymcode.openpayments.httpsignatures.Component
import io.github.geovannymcode.openpayments.httpsignatures.HttpHeaders
import io.github.geovannymcode.openpayments.httpsignatures.HttpMessageSigner
import io.github.geovannymcode.openpayments.httpsignatures.HttpRequest
import io.github.geovannymcode.openpayments.httpsignatures.SignatureParameters
import io.github.geovannymcode.openpayments.httpsignatures.jvm.OpenPaymentsSmoke.stringField
import io.github.geovannymcode.openpayments.httpsignatures.withContentDigest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.time.Duration
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import java.net.http.HttpRequest as JdkHttpRequest

/**
 * Prueba de interoperabilidad: un servidor real de Open Payments debe aceptar las firmas de este
 * módulo. Los demás tests prueban conformidad con el RFC; este prueba que el servidor reconstruye
 * la misma signature base y valida la firma, lo que solo se demuestra con un grant aprobado.
 *
 * Requiere `OP_WALLET_ADDRESS`, `OP_KEY_ID` y `OP_PRIVATE_KEY_PATH`; si falta alguna, se salta.
 * Se ejecuta con `./gradlew :http-signatures:integrationTest`.
 *
 * Nunca imprime la llave privada, el access token, la firma, la signature base ni el cuerpo de las
 * respuestas: solo códigos HTTP, códigos de error saneados e identificadores públicos.
 */
@Tag("integration")
class OpenPaymentsIntegrationSmokeTest {
    private val client: HttpClient = HttpClient.newBuilder()
        // HTTP/1.1 garantiza que el JDK envíe Content-Length, que es un componente cubierto.
        .version(HttpClient.Version.HTTP_1_1)
        .connectTimeout(Duration.ofSeconds(15))
        .build()

    /**
     * Descubre el auth server desde la wallet address, verifica que la llave esté registrada y pide
     * un grant de `incoming-payment` firmado. Pasa solo si el servidor devuelve un grant aprobado.
     */
    @Test
    fun should_accept_signed_incoming_payment_grant_request() {
        val walletAddress = requiredEnv("OP_WALLET_ADDRESS").let(::toUrl)
        val keyId = requiredEnv("OP_KEY_ID")
        // El keyid viaja en Signature-Input: si por error contiene la llave privada, se detiene aquí
        // sin mostrar el valor.
        assertFalse(
            looksLikeKeyMaterial(keyId),
            "OP_KEY_ID parece contener una llave privada, no un key id. Usa el 'kid' de la llave en el " +
                "test wallet (por ejemplo un UUID). No se muestra el valor; si llegó a imprimirse, rota la llave.",
        )
        val privateKeyPath = requiredEnv("OP_PRIVATE_KEY_PATH")

        val authServer = fetchAuthServer(walletAddress)
        val body = OpenPaymentsSmoke.incomingPaymentGrantBody(walletAddress)
        val request = HttpRequest(
            method = "POST",
            uri = authServer,
            headers = HttpHeaders.of(
                "Content-Type" to "application/json",
                "Content-Length" to body.size.toString(),
                "Accept" to "application/json",
            ),
            body = body,
        ).withContentDigest()

        val keyFile = Path.of(privateKeyPath).toAbsolutePath()
        assertTrue(Files.isRegularFile(keyFile), "OP_PRIVATE_KEY_PATH no apunta a un archivo: $keyFile")
        val ed25519 = Ed25519Signer.load(Files.readAllBytes(keyFile))
        verifyKeyRegistration(walletAddress, keyId, ed25519)

        val signature = HttpMessageSigner(ed25519).sign(
            request = request,
            components = listOf(
                Component.Method,
                Component.TargetUri,
                Component.Field("content-digest"),
                Component.Field("content-length"),
                Component.Field("content-type"),
            ),
            parameters = SignatureParameters(created = System.currentTimeMillis() / 1000, keyId = keyId),
        )

        val response = send(signature.applyTo(request), body)
        println("POST $authServer -> ${response.statusCode()}")

        assertNull(OpenPaymentsSmoke.grantFailure(response.statusCode(), response.body()))
        println("Firma aceptada; grant de incoming-payment aprobado con access token (no se imprime).")
    }

    /** Obtiene `authServer` de la wallet address; no se hardcodea porque depende del tenant. */
    private fun fetchAuthServer(walletAddress: String): String {
        val response = client.send(OpenPaymentsSmoke.discoveryRequest(walletAddress), HttpResponse.BodyHandlers.ofString())
        assertEquals(200, response.statusCode(), "GET $walletAddress devolvió ${response.statusCode()}")
        val walletDocument = OpenPaymentsSmoke.parseJson(response.body()) as? JsonObject
        return assertNotNull(walletDocument?.stringField("authServer"), "La wallet address no publica authServer")
    }

    /**
     * Envía la petición firmada con el cliente del JDK, transmitiendo exactamente los bytes sobre
     * los que se calculó `Content-Digest`.
     */
    private fun send(request: HttpRequest, body: ByteArray): HttpResponse<String> {
        val builder = JdkHttpRequest.newBuilder(URI.create(request.uri))
            .timeout(OpenPaymentsSmoke.REQUEST_TIMEOUT)
            .POST(JdkHttpRequest.BodyPublishers.ofByteArray(body))
        request.headers.toList()
            // Content-Length es un header restringido en java.net.http: el cliente lo calcula a partir
            // del cuerpo y coincide con el valor firmado porque los bytes son los mismos.
            .filterNot { (name, _) -> name.equals("Content-Length", ignoreCase = true) }
            .forEach { (name, value) -> builder.header(name, value) }
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString())
    }

    /**
     * Preflight antes del POST: Rafiki busca en `<client>/jwks.json` una llave con `kid == keyid`
     * y, si no la encuentra, responde `400 invalid_client` sin llegar a verificar la firma. Aquí se
     * comprueba que [keyId] esté publicado y que la llave privada corresponda a esa llave pública,
     * firmando un mensaje de prueba y verificándolo con la `x` del JWK. Los mensajes solo incluyen
     * datos públicos (URL del JWKS y `kid` publicados), nunca la llave privada.
     */
    private fun verifyKeyRegistration(walletAddress: String, keyId: String, signer: Ed25519Signer) {
        val jwksUrl = "${walletAddress.trimEnd('/')}/jwks.json"
        val response = client.send(OpenPaymentsSmoke.discoveryRequest(jwksUrl), HttpResponse.BodyHandlers.ofString())
        assertEquals(200, response.statusCode(), "GET $jwksUrl devolvió ${response.statusCode()}")

        val jwks = OpenPaymentsSmoke.parseJson(response.body()) as? JsonObject
        val publishedKeys = (jwks?.get("keys") as? JsonArray).orEmpty().filterIsInstance<JsonObject>()
        val publishedKids = publishedKeys.map { it.stringField("kid") }
        val registeredX = publishedKeys.firstOrNull { it.stringField("kid") == keyId }?.stringField("x")
        assertNotNull(registeredX, "OP_KEY_ID no coincide con ningún kid publicado en $jwksUrl. kid publicados: $publishedKids")

        val probe = "open-payments-kotlin key probe".encodeToByteArray()
        assertTrue(
            Ed25519TestKeys.verify(publicKeyFromJwkX(registeredX), probe, signer.sign(probe)),
            "La llave de OP_PRIVATE_KEY_PATH no corresponde a la llave pública publicada con OP_KEY_ID en $jwksUrl",
        )
        println("Preflight: OP_KEY_ID publicado en el JWKS y la llave privada corresponde a esa llave pública.")
    }

    /** Convierte la coordenada `x` (base64url) de un JWK Ed25519 en una llave pública X.509. */
    private fun publicKeyFromJwkX(x: String): PublicKey {
        val spkiPrefix = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)
        val raw = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL).decode(x)
        return KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(spkiPrefix + raw))
    }

    /** Detecta PEM, PKCS#8 en base64 o una semilla de 32 bytes en base64. */
    private fun looksLikeKeyMaterial(value: String): Boolean {
        if ("PRIVATE KEY" in value || value.startsWith(PKCS8_ED25519_BASE64_PREFIX)) return true
        val decodedSize = runCatching { Base64.decode(value).size }.getOrNull()
        return decodedSize == 32 || decodedSize == 48
    }

    /** Lee una variable obligatoria; si falta, salta la prueba en lugar de fallar, para que CI siga verde. */
    private fun requiredEnv(name: String): String {
        val value = System.getenv(name)
        assumeTrue(!value.isNullOrBlank(), "Falta la variable de entorno $name; se salta la prueba de integración")
        return value!!
    }

    /** Acepta tanto la URL como el payment pointer (`$wallet.example/alice`). */
    private fun toUrl(walletAddress: String): String =
        if (walletAddress.startsWith("$")) "https://${walletAddress.substring(1)}" else walletAddress

    private companion object {
        /** Cabecera DER de una llave privada Ed25519 PKCS#8, codificada en base64. */
        const val PKCS8_ED25519_BASE64_PREFIX = "MC4CAQAwBQYDK2VwBCIEI"
    }
}
