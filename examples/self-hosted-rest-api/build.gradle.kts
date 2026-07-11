plugins {
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dependency.management)
}

dependencies {
    // Import the shared core module
    implementation(project(":w3auth-core"))

    // Web + security + validation
    implementation(libs.spring.boot.starter.webmvc)
    implementation(libs.spring.boot.starter.security)
    implementation(libs.spring.boot.starter.validation)
    implementation(libs.spring.boot.starter.actuator)

    // Durable data (Postgres via JPA + Flyway) and ephemeral data (Redis)
    implementation(libs.spring.boot.starter.data.jpa)
    implementation(libs.spring.boot.starter.data.redis)
    implementation(libs.spring.boot.starter.flyway)
    implementation(libs.flyway.database.postgresql)
    runtimeOnly(libs.postgresql)

    // web3j RPC client — eth_getCode + eth_call for EIP-1271 smart-contract wallet verification.
    // Isolated here in the application/infrastructure layer.
    implementation(libs.web3j.core)

    // JWT API and Runtime Engines
    implementation(libs.jjwt.api)
    runtimeOnly(libs.jjwt.impl)
    runtimeOnly(libs.jjwt.jackson)

    // Testing
    testImplementation(libs.archunit.junit5)
    testImplementation(libs.spring.boot.starter.test)
    testImplementation(libs.spring.boot.starter.security.test)
    testImplementation(libs.spring.boot.starter.data.jpa.test)
    testImplementation(libs.spring.boot.testcontainers)
    testImplementation(libs.testcontainers.junit.jupiter)
    testImplementation(libs.testcontainers.postgresql)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
