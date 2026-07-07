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
    testImplementation(libs.keycloak.admin.client)

    // Web3j crypto required for signing test vectors
    testImplementation(libs.web3j.crypto)

    // Test dependencies matching standalone-api to align the Testcontainers runtime environment
    testImplementation("org.springframework.boot:spring-boot-starter-test:${libs.plugins.spring.boot.get().version.requiredVersion}")
    testImplementation("org.springframework.boot:spring-boot-testcontainers:${libs.plugins.spring.boot.get().version.requiredVersion}")

    // Testcontainers
    testImplementation(libs.testcontainers.junit.jupiter)

    // Unit testing
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj.core)
    testImplementation(libs.mockito.core)
    testImplementation(libs.mockito.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
    testRuntimeOnly(libs.jjwt.impl)
    testRuntimeOnly(libs.jjwt.jackson)
    testRuntimeOnly("org.slf4j:slf4j-simple:2.0.9")
}

tasks.jar {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get()
        .filter { !it.name.contains("bcprov") } // Exclude BouncyCastle since Keycloak provides it
        .map { if (it.isDirectory) it else zipTree(it) }
    )
}

tasks.test {
    // Force Gradle to package the fat JAR before running integration tests
    dependsOn(tasks.jar)
    
    // Pass the absolute path of the built fat JAR to the test runner
    systemProperty("plugin.jar.path", tasks.jar.get().archiveFile.get().asFile.absolutePath)
}
