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
    useJUnitPlatform {
        excludeTags("integration")
    }
}

// Pruebas contra servidores reales de Open Payments. Se saltan si faltan las credenciales.
tasks.register<Test>("integrationTest") {
    description = "Runs interoperability tests against a real Open Payments server."
    group = LifecycleBasePlugin.VERIFICATION_GROUP
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    useJUnitPlatform {
        includeTags("integration")
    }
    // Depende de la red y de credenciales externas: nunca se considera al día.
    outputs.upToDateWhen { false }
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = true
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
