dependencies {
    // Import the shared core module
    implementation(project(":w3auth-core"))

    // Keycloak SPI dependencies provided by the server environment at runtime
    compileOnly(libs.keycloak.core)
    compileOnly(libs.keycloak.server.spi)
    compileOnly(libs.keycloak.server.spi.private)
    compileOnly(libs.keycloak.services)

    // Keycloak dependencies needed during unit test compilation
    testImplementation(libs.keycloak.core)
    testImplementation(libs.keycloak.server.spi)
    testImplementation(libs.keycloak.server.spi.private)
    testImplementation(libs.keycloak.services)

    // Web3j crypto required for signing test vectors
    testImplementation(libs.web3j.crypto)

    // Unit testing
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj.core)
    testImplementation(libs.mockito.core)
    testImplementation(libs.mockito.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
    testRuntimeOnly(libs.jjwt.impl)
    testRuntimeOnly(libs.jjwt.jackson)
}
