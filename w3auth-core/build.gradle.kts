dependencies {
    // Cryptography and signature verification
    implementation(libs.web3j.crypto)
    implementation(libs.bouncycastle.bcprov)
    
    // JWT API for session tokens
    implementation(libs.jjwt.api)
    
    // Testing
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj.core)
    testImplementation(libs.mockito.core)
    testImplementation(libs.mockito.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
    testRuntimeOnly(libs.jjwt.impl)
    testRuntimeOnly(libs.jjwt.jackson)
}
