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
    private val client: HttpClient = OpenPaymentsSmoke.newHttpClient()

    /**
     * Descubre el auth server desde la wallet address, verifica que la llave esté registrada y pide
     * un grant de `incoming-payment` firmado. Pasa solo si el servidor devuelve un grant aprobado.
     */
    @Test
    fun should_accept_signed_incoming_payment_grant_request() {
        val walletAddress = requiredEnv("OP_WALLET_ADDRESS").let(OpenPaymentsSmoke::normalizeWalletAddress)
        val keyId = requiredEnv("OP_KEY_ID")
        // The keyid travels in Signature-Input: stop here, without echoing the value, if it holds a private key.
        assertFalse(
            OpenPaymentsSmoke.looksLikeKeyMaterial(keyId),
            "OP_KEY_ID looks like a private key, not a key id. Use the key's 'kid' from the test wallet " +
                "(for example a UUID). The value is not shown; if it was ever printed, rotate the key.",
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

    /**
     * Fetches `authServer` from the wallet address, since it depends on the tenant, and requires it
     * to be HTTPS before the signed request is sent there.
     */
    private fun fetchAuthServer(walletAddress: String): String {
        val response = client.send(OpenPaymentsSmoke.discoveryRequest(walletAddress), HttpResponse.BodyHandlers.ofString())
        assertEquals(200, response.statusCode(), "GET $walletAddress devolvió ${response.statusCode()}")
        val walletDocument = OpenPaymentsSmoke.parseJson(response.body()) as? JsonObject
        val authServer = assertNotNull(walletDocument?.stringField("authServer"), "The wallet address does not publish authServer")
        return OpenPaymentsSmoke.requireHttpsAuthServer(authServer)
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

    /** Lee una variable obligatoria; si falta, salta la prueba en lugar de fallar, para que CI siga verde. */
    private fun requiredEnv(name: String): String {
        val value = System.getenv(name)
        assumeTrue(!value.isNullOrBlank(), "Falta la variable de entorno $name; se salta la prueba de integración")
        return value!!
    }
}
