package com.w3auth.backend.verification;

import com.w3auth.backend.identity.Namespace;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;

@ExtendWith(MockitoExtension.class)
class NamespaceRoutingSignatureVerifierTest {

    @Mock
    private SignatureVerifier ethereumVerifier;

    @Mock
    private SignatureVerifier solanaVerifier;

    @Test
    void verify_routesToEthereumVerifierForEip155() throws VerificationException {
        AuthMessage eip155Message = new SiweMessage(
                "example.com",
                "0x0000000000000000000000000000000000000000",
                "https://example.com",
                "1",
                "1",
                "nonce",
                Instant.now(),
                Instant.now().plusSeconds(60)
        );
        VerificationRequest request = new VerificationRequest(eip155Message, "raw-msg", "sig");
        VerifiedIdentity expectedIdentity = new VerifiedIdentity("0xaddress");
        when(ethereumVerifier.verify(request)).thenReturn(expectedIdentity);

        NamespaceRoutingSignatureVerifier verifier = new NamespaceRoutingSignatureVerifier(ethereumVerifier, solanaVerifier);
        VerifiedIdentity result = verifier.verify(request);

        assertThat(result).isEqualTo(expectedIdentity);
        verify(ethereumVerifier).verify(request);
    }

    @Test
    void verify_routesToSolanaVerifierForSolana() throws VerificationException {
        AuthMessage solanaMessage = new SiwsMessage(
                "example.com",
                "586Z7H2vpX9qNhN2T4e9Utugie3ogjbxzGaMtM3E6HR5",
                "https://example.com",
                "1",
                "mainnet",
                "nonce",
                Instant.now(),
                Instant.now().plusSeconds(60)
        );
        VerificationRequest request = new VerificationRequest(solanaMessage, "raw-msg", "sig");
        VerifiedIdentity expectedIdentity = new VerifiedIdentity("sol-address");
        when(solanaVerifier.verify(request)).thenReturn(expectedIdentity);

        NamespaceRoutingSignatureVerifier verifier = new NamespaceRoutingSignatureVerifier(ethereumVerifier, solanaVerifier);
        VerifiedIdentity result = verifier.verify(request);

        assertThat(result).isEqualTo(expectedIdentity);
        verify(solanaVerifier).verify(request);
    }
}
