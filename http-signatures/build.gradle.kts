import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
}

kotlin {
    explicitApi()
    jvmToolchain(25)
    compilerOptions {
        jvmTarget = JvmTarget.JVM_21
    }
}

java {
    targetCompatibility = JavaVersion.VERSION_21
}

dependencies {
    // RFC 9421 sin dependencias de runtime: solo se permiten dependencias de test.
    testImplementation(libs.kotlin.test)
}

tasks.test {
    useJUnitPlatform()
}
