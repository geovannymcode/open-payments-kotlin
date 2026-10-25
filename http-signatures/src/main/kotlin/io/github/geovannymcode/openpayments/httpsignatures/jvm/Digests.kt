package io.github.geovannymcode.openpayments.httpsignatures.jvm

import io.github.geovannymcode.openpayments.httpsignatures.DigestAlgorithm
import java.security.MessageDigest

// Único punto donde ContentDigest depende de java.*: en Kotlin Multiplatform pasa a ser un `actual`.
internal fun DigestAlgorithm.hash(input: ByteArray): ByteArray {
    val jcaName = when (this) {
        DigestAlgorithm.SHA_256 -> "SHA-256"
        DigestAlgorithm.SHA_512 -> "SHA-512"
    }
    return MessageDigest.getInstance(jcaName).digest(input)
}
