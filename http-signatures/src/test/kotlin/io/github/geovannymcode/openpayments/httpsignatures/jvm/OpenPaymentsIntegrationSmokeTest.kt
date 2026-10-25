package io.github.geovannymcode.openpayments.httpsignatures.jvm

import io.github.geovannymcode.openpayments.httpsignatures.Component
import io.github.geovannymcode.openpayments.httpsignatures.ContentDigest
import io.github.geovannymcode.openpayments.httpsignatures.HttpHeaders
import io.github.geovannymcode.openpayments.httpsignatures.HttpMessageSigner
import io.github.geovannymcode.openpayments.httpsignatures.HttpRequest
import io.github.geovannymcode.openpayments.httpsignatures.HttpSignature
import io.github.geovannymcode.openpayments.httpsignatures.SignatureParameters
import io.github.geovannymcode.openpayments.httpsignatures.withContentDigest
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail
import java.net.http.HttpRequest as JdkHttpRequest

/**
 * Prueba de interoperabilidad: un servidor real de Open Payments debe aceptar las firmas de este
 * módulo. Los demás tests prueban conformidad con el RFC; este prueba que el servidor reconstruye
 * la misma signature base.
 *
 * Requiere `OP_WALLET_ADDRESS`, `OP_KEY_ID` y `OP_PRIVATE_KEY_PATH`; si falta alguna, se salta.
 * Se ejecuta con `./gradlew :http-signatures:integrationTest`.
 *
 * Nunca se imprimen la llave privada ni el access token.
 */
@Tag("integration")
class OpenPaymentsIntegrationSmokeTest {
    private val client: HttpClient = HttpClient.newBuilder()
        // HTTP/1.1 garantiza que el JDK envíe Content-Length, que es un componente cubierto.
        .version(HttpClient.Version.HTTP_1_1)
        .connectTimeout(Duration.ofSeconds(15))
        .build()

    @Test
    fun should_accept_signed_incoming_payment_grant_request() {
        val walletAddress = requiredEnv("OP_WALLET_ADDRESS").let(::toUrl)
        val keyId = requiredEnv("OP_KEY_ID")
        val privateKeyPath = requiredEnv("OP_PRIVATE_KEY_PATH")

        val authServer = fetchAuthServer(walletAddress)
        val body = """
            {"access_token":{"access":[{"type":"incoming-payment","actions":["create","read","list"]}]},"client":"$walletAddress"}
        """.trim().encodeToByteArray()

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

        val signer = HttpMessageSigner(Ed25519Signer.load(Files.readAllBytes(Path.of(privateKeyPath))))
        val signature = signer.sign(
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
        val status = response.statusCode()
        println("POST $authServer -> $status")

        when (status) {
            401, 403 -> fail("El servidor rechazó la firma ($status).\n" + diagnostics(signature, request, response))
            400 -> {
                val errorCode = jsonString(response.body(), "code")
                assertEquals(
                    "invalid_request",
                    errorCode,
                    "400 con código '$errorCode': no es un problema de forma del cuerpo. ${response.body()}",
                )
                println("Firma aceptada; el servidor rechazó la forma del cuerpo (400 invalid_request): ${response.body()}")
            }
            200 -> {
                val responseBody = response.body()
                assertTrue("\"access_token\"" in responseBody, "200 sin access_token en la respuesta")
                assertFalse("\"interact\"" in responseBody, "Se esperaba un grant aprobado, no un flujo de interacción")
                println("Firma aceptada; grant de incoming-payment aprobado con access token (no se imprime).")
            }
            else -> fail("Estado inesperado $status: ${response.body()}")
        }
    }

    private fun fetchAuthServer(walletAddress: String): String {
        val response = client.send(
            JdkHttpRequest.newBuilder(URI.create(walletAddress)).header("Accept", "application/json").GET().build(),
            HttpResponse.BodyHandlers.ofString(),
        )
        assertEquals(200, response.statusCode(), "GET $walletAddress devolvió ${response.statusCode()}")
        return assertNotNull(jsonString(response.body(), "authServer"), "La wallet address no publica authServer")
    }

    private fun send(request: HttpRequest, body: ByteArray): HttpResponse<String> {
        val builder = JdkHttpRequest.newBuilder(URI.create(request.uri))
            .timeout(Duration.ofSeconds(30))
            // Se envían los mismos bytes sobre los que se calculó Content-Digest.
            .POST(JdkHttpRequest.BodyPublishers.ofByteArray(body))
        request.headers.toList()
            // Content-Length es un header restringido en java.net.http: el cliente lo calcula a partir
            // del cuerpo y coincide con el valor firmado porque los bytes son los mismos.
            .filterNot { (name, _) -> name.equals("Content-Length", ignoreCase = true) }
            .forEach { (name, value) -> builder.header(name, value) }
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString())
    }

    private fun diagnostics(signature: HttpSignature, request: HttpRequest, response: HttpResponse<String>): String =
        buildString {
            appendLine("--- signature base ---")
            appendLine(signature.signatureBase.value)
            appendLine("--- headers de firma ---")
            appendLine("Signature-Input: ${signature.signatureInput}")
            appendLine("Signature: ${signature.signatureHeader}")
            appendLine("${ContentDigest.HEADER_NAME}: ${request.headers.values(ContentDigest.HEADER_NAME).single()}")
            appendLine("--- respuesta ---")
            append(response.body())
        }

    private fun requiredEnv(name: String): String {
        val value = System.getenv(name)
        assumeTrue(!value.isNullOrBlank(), "Falta la variable de entorno $name; se salta la prueba de integración")
        return value!!
    }

    /** Acepta tanto la URL como el payment pointer (`$wallet.example/alice`). */
    private fun toUrl(walletAddress: String): String =
        if (walletAddress.startsWith("$")) "https://${walletAddress.substring(1)}" else walletAddress

    /** Extrae un valor de texto de un JSON plano; suficiente para esta prueba y sin dependencias. */
    private fun jsonString(json: String, key: String): String? =
        Regex("\"${Regex.escape(key)}\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").find(json)?.groupValues?.get(1)?.replace("\\/", "/")
}
