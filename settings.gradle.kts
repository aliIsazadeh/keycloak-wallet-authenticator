rootProject.name = "keycloak-wallet-authenticator"
include("w3auth-core")
// The Spring Boot REST API is a reference example of self-hosting, not the product.
// It lives under examples/ but stays a Gradle subproject so it is built and tested with the rest.
include(":examples:self-hosted-rest-api")
project(":examples:self-hosted-rest-api").projectDir = file("examples/self-hosted-rest-api")
include("w3auth-keycloak-plugin")
