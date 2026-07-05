package com.w3auth.backend.verification;

import com.w3auth.backend.identity.Namespace;
import java.time.Instant;

/**
 * Common interface for parsed authentication messages across different namespaces.
 *
 * <p>Implemented by {@link SiweMessage} (EIP-155) and {@link SiwsMessage} (Solana).
 */
public sealed interface AuthMessage permits SiweMessage, SiwsMessage {

    String domain();

    String address();

    String uri();

    String version();

    String chainId();

    String nonce();

    Instant issuedAt();

    Instant expiresAt();

    Namespace namespace();
}
