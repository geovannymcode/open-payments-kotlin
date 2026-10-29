## Summary

Provide a concise summary of the changes made, the motivation behind them, and how they solve the problem.

## Related Issues

Fixes #(issue) or Closes #(issue)

## Type of Change

- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Breaking change (fix or feature causing existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Refactoring or build configuration update

## Verification and Testing

Describe the steps taken to verify the changes. Include commands executed and results observed.

- [ ] Executed `./gradlew test` (unit tests pass)
- [ ] Executed `./gradlew build` (full build passes)
- [ ] Executed `./gradlew :http-signatures:integrationTest` (if testing against live Open Payments server)

## Contributor Checklist

- [ ] My branch is created from `develop` and targets `develop`.
- [ ] My commit messages follow the Conventional Commits specification.
- [ ] All unit and verification tests pass locally.
- [ ] No unnecessary runtime dependencies have been introduced (the `http-signatures` module must maintain zero runtime dependencies).
- [ ] All public APIs have explicit visibility modifiers, explicit return types, and KDoc documentation as required by `explicitApi()`.
- [ ] No secrets, private keys, authentication tokens, or personal credentials appear in source code, commit history, or logs.
- [ ] Code follows the official Kotlin code style convention configured in the repository.
