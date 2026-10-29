# Contributor Guide

Thank you for contributing to `open-payments-kotlin`. This document outlines the technical workflow, repository conventions, test execution procedures, and security guidelines for contributors.

## Code of Conduct

All contributors and maintainers are expected to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it to understand the community standards and expectations.

## Prerequisites and Environment Setup

Ensure the following tools are installed on your workstation:

- Java Development Kit (JDK): JDK 25 is required. The project uses the Gradle Foojay toolchains resolver and targets JVM 21 bytecode compatibility. Eclipse Temurin JDK 25 is recommended.
- Git: Version 2.30 or newer.
- Gradle: The project provides the Gradle wrapper (`gradlew` and `gradlew.bat`). Installing an external Gradle distribution is not required.

To clone the repository and verify the initial setup:

```bash
git clone https://github.com/geovannymcode/open-payments-kotlin.git
cd open-payments-kotlin
./gradlew --version
```

On Windows command line or PowerShell, use `.\gradlew.bat` in place of `./gradlew`.

## Branching Model

The repository adheres to the following branching strategy:

- `develop`: The primary integration branch. All ongoing development, bug fixes, and feature additions must be merged into `develop`.
- `main`: The stable production branch reflecting released versions.
- Feature branches (`feature/*`): All work must be conducted in dedicated feature branches branched directly from `develop`.

Pull requests must target the `develop` branch. Pull requests opened against `main` will be declined or requested to be retargeted to `develop`.

### Contribution Workflow

1. Update your local copy of `develop`:
   ```bash
   git checkout develop
   git pull origin develop
   ```
2. Create a new feature branch from `develop`:
   ```bash
   git checkout -b feature/my-feature-name
   ```
3. Implement your changes following repository coding standards and architecture rules.
4. Run unit tests and verification builds locally.
5. Commit your changes using Conventional Commits format.
6. Push your branch to your remote fork or repository:
   ```bash
   git push -u origin feature/my-feature-name
   ```
7. Open a Pull Request targeting the `develop` branch on GitHub.

## Commit Message Conventions

Commit messages must follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```text
<type>(<scope>): <description>
```

### Allowed Types

- `feat`: A new feature or capability.
- `fix`: A bug fix.
- `docs`: Documentation changes only.
- `style`: Changes that do not affect code meaning (formatting, whitespace, semi-colons).
- `refactor`: Code changes that neither fix a bug nor add a feature.
- `perf`: Code changes improving performance.
- `test`: Adding missing tests or correcting existing tests.
- `build`: Changes that affect the build system or external dependencies (Gradle, version catalog).
- `ci`: Changes to CI configuration files and scripts (GitHub Actions).
- `chore`: Routine maintenance tasks, repository bootstrapping, or non-production changes.

### Scope

The scope is optional but recommended. When working on a specific module or subcomponent, use the module name:

- `http-signatures`
- `core`
- `ci`

### Rules

- Use the imperative, present tense: "add" instead of "added" or "adds".
- Do not capitalize the first letter of the description.
- Do not place a period at the end of the subject line.
- Keep the subject line concise (under 72 characters).

### Examples from Repository History

- `feat(http-signatures): implement RFC 9421 signing with Ed25519`
- `fix(http-signatures): keep explicit port in @target-uri and enforce ASCII signature base`
- `ci: add GitHub Actions build workflow`
- `chore: bootstrap multi-module Gradle build`

## Building and Testing

The project uses a multi-module Gradle build configuration.

### Build the Project

To compile all Kotlin sources and assemble output archives:

```bash
# Linux / macOS
./gradlew build

# Windows PowerShell
.\gradlew.bat build
```

The `build` task compiles source sets, verifies explicit API definitions, and executes unit tests.

### Running Unit Tests

Unit tests cover RFC 9421 component handling, serialization, canonicalization, and cryptographic signing without external network calls. Unit tests automatically exclude integration tests:

```bash
# Linux / macOS
./gradlew test

# Windows PowerShell
.\gradlew.bat test
```

To run unit tests for a specific module:

```bash
./gradlew :http-signatures:test
```

### Running Integration Tests

The integration test suite (`:http-signatures:integrationTest`) validates interoperability against a live Open Payments compliant server. The test executes the full GNAP incoming payment grant flow using Ed25519 signed requests.

To run the integration tests:

```bash
# Linux / macOS
./gradlew :http-signatures:integrationTest

# Windows PowerShell
.\gradlew.bat :http-signatures:integrationTest
```

If the required environment variables are not set on the host system, the integration test is skipped automatically. The build succeeds with a skipped test status:

```text
OpenPaymentsIntegrationSmokeTest > should_accept_signed_incoming_payment_grant_request() SKIPPED
```

This behavior ensures continuous integration pipelines remain green when external credentials are absent.

## Integration Test Configuration with Test Wallet Credentials

To execute integration tests against a live server, contributors must supply their own test wallet credentials.

### Required Environment Variables

The test runner looks for three environment variables:

1. `OP_WALLET_ADDRESS`:
   - Description: The complete URL of your Open Payments test wallet account.
   - Format: Absolute HTTPS URL (e.g. `https://ilp.rafiki.money/your-account`) or payment pointer syntax (e.g. `$ilp.rafiki.money/your-account`).
   - Requirements: The wallet address must resolve to a valid JSON document publishing an `authServer` endpoint and a public JWKS (`/jwks.json`). It must not contain user info, explicit ports, queries, or fragments.
2. `OP_KEY_ID`:
   - Description: The public key identifier (`kid`) assigned to your Ed25519 public key registered in the test wallet.
   - Format: String matching the `kid` entry published in `<walletAddress>/jwks.json` (for example, a UUID).
   - Security rule: This variable must contain only the public key identifier. It must never contain private key data. The test suite validates this parameter before sending requests.
3. `OP_PRIVATE_KEY_PATH`:
   - Description: File path to your local Ed25519 private key.
   - Format: Absolute file path, or relative path resolved from the repository root directory.
   - Supported key formats: Raw 32-byte binary seed (RFC 8032), or PKCS#8 PEM format containing `-----BEGIN PRIVATE KEY-----`.

### Obtaining Test Wallet Credentials

1. Register an account with an Open Payments test wallet provider (such as the Rafiki test network or Interledger test environment).
2. Generate an Ed25519 key pair:
   - Generate a private key in PKCS#8 PEM format using OpenSSL or equivalent tooling.
   - Extract the public key coordinates (`x` coordinate for Ed25519 JWK).
3. In the test wallet management dashboard, add your public key to your wallet address.
4. Record the generated Key ID (`kid`) assigned to that key.
5. Verify in your web browser that `https://<your-wallet-address>/jwks.json` displays your key with the matching `kid`.

### Secure Credential Management

Protecting private keys and preventing credential leaks is critical:

- Repository ignore rules: The repository `.gitignore` configuration explicitly ignores the `.secrets/` directory along with `private.key`, `*.pem`, `.env`, and `local.properties`.
- Storage recommendation: Save your private key inside the `.secrets/` directory in the repository root (e.g. `.secrets/private.key`). Because `.secrets/` is ignored by Git, keys stored there will not be tracked or committed.
- Path resolution: The Gradle integration test task specifies `workingDir = rootDir`. As a result, relative paths such as `.secrets/private.key` resolve reliably across operating systems.
- Sanitized logging: The integration test client is designed never to print private keys, bearer access tokens, signature bases, or full response bodies to standard output or build logs. Only HTTP status codes and sanitized GNAP error codes are emitted.
- Never commit credentials: Never add keys or environment configuration files to Git commits or PR descriptions.

### Setting Variables and Executing Tests

#### Linux / macOS

```bash
export OP_WALLET_ADDRESS="https://ilp.rafiki.money/your-account"
export OP_KEY_ID="your-key-uuid-or-id"
export OP_PRIVATE_KEY_PATH=".secrets/private.key"

./gradlew :http-signatures:integrationTest
```

Alternatively, invoke Gradle with inline environment variables:

```bash
OP_WALLET_ADDRESS="https://ilp.rafiki.money/your-account" \
OP_KEY_ID="your-key-uuid-or-id" \
OP_PRIVATE_KEY_PATH=".secrets/private.key" \
./gradlew :http-signatures:integrationTest
```

#### Windows PowerShell

```powershell
$env:OP_WALLET_ADDRESS = "https://ilp.rafiki.money/your-account"
$env:OP_KEY_ID = "your-key-uuid-or-id"
$env:OP_PRIVATE_KEY_PATH = ".secrets/private.key"

.\gradlew.bat :http-signatures:integrationTest
```

## Repository Standards and Architecture

### Explicit API Mode

The project enforces Kotlin Explicit API mode (`explicitApi()`):

- All public declarations (classes, interfaces, methods, properties) must have an explicit visibility modifier (`public`, `internal`, `private`).
- Return types must be explicitly declared on all public and internal declarations.
- All public declarations must include comprehensive KDoc documentation explaining behavior, parameters, and exceptions.

### Dependency Constraints

- The `http-signatures` module must maintain zero third-party runtime dependencies.
- Libraries such as `kotlin-test` and `kotlinx-serialization-json` are restricted to test configurations (`testImplementation`).
- Avoid adding third-party runtime dependencies without maintainer discussion and architectural review.

### Kotlin Multiplatform Readiness

- Core signing contracts and RFC 9421 parsing logic reside in package `io.github.geovannymcode.openpayments.httpsignatures`. This code must avoid Java-specific types (`java.*`) to maintain compatibility with future Kotlin Multiplatform targets.
- Java-specific implementations (such as Java Cryptography Architecture adapters or JDK HTTP clients) reside strictly in the JVM-specific subpackage `io.github.geovannymcode.openpayments.httpsignatures.jvm`.

### Code Formatting

The repository enforces the official Kotlin style guide:

```properties
kotlin.code.style=official
```

Ensure imports are organized cleanly and unnecessary files are not committed.

## Submitting a Pull Request

Before submitting a pull request, ensure the following steps have been completed:

1. Confirm your branch is rebased on the latest `origin/develop`:
   ```bash
   git fetch origin
   git rebase origin/develop
   ```
2. Run the complete build and verification suite:
   ```bash
   ./gradlew build
   ```
3. If your changes affect signature exchange or integration components, run integration tests with your test credentials:
   ```bash
   ./gradlew :http-signatures:integrationTest
   ```
4. Verify that `git status` shows no untracked secret files or unintended changes.
5. Ensure commit messages follow Conventional Commits.
6. Push your branch and open a Pull Request targeting `develop`.
7. Fill out all sections of the Pull Request template, including the confirmation checklist.
