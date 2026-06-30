plugins {
    java
    id("org.springframework.boot") version "4.1.0"
    id("io.spring.dependency-management") version "1.1.7"
}

group = "com.w3auth"
version = "0.0.1-SNAPSHOT"
description = "W3-Auth — wallet authentication backend"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    // Web + security + validation
    implementation("org.springframework.boot:spring-boot-starter-webmvc")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-actuator")

    // Durable data (Postgres via JPA + Flyway) and ephemeral data (Redis)
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-data-redis")
    implementation("org.springframework.boot:spring-boot-starter-flyway")
    implementation("org.flywaydb:flyway-database-postgresql")
    runtimeOnly("org.postgresql:postgresql")

    // Ethereum crypto (ecrecover, Keccak-256, secp256k1)
    implementation("org.web3j:crypto:4.12.3")
    // web3j RPC client — eth_getCode + eth_call for EIP-1271 smart-contract wallet verification
    implementation("org.web3j:core:4.12.3")
    // Ed25519 for Solana signature verification. web3j pulls this transitively, but the verifier
    // imports org.bouncycastle directly, so the dependency must be declared explicitly.
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")

    // JWT (HS256 access tokens). jjwt-api at compile scope; impl + jackson are runtime plugins.
    implementation("io.jsonwebtoken:jjwt-api:0.12.6")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.12.6")
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.12.6")

    // Testing
    testImplementation("com.tngtech.archunit:archunit-junit5:1.4.2")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.boot:spring-boot-starter-security-test")
    testImplementation("org.springframework.boot:spring-boot-starter-data-jpa-test")
    // Testcontainers core (org.testcontainers:testcontainers) is pulled in
    // transitively by spring-boot-testcontainers and provides GenericContainer,
    // used for the Redis container (no dedicated testcontainers-redis module).
    testImplementation("org.springframework.boot:spring-boot-testcontainers")
    testImplementation("org.testcontainers:testcontainers-junit-jupiter")
    testImplementation("org.testcontainers:testcontainers-postgresql")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test> {
    useJUnitPlatform()
}
