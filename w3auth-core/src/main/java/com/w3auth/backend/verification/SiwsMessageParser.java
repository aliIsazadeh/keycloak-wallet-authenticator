package com.w3auth.backend.verification;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Set;

/**
 * Parses the SIWS (Sign-In With Solana) message string.
 * Supports standard SIWS formats, including optional fields (Not Before, Request ID,
 * Resources) and statement blocks.
 */
public final class SiwsMessageParser {

    private static final String FIRST_LINE_SUFFIX = " wants you to sign in with your Solana account:";
    private static final String PREFIX_URI = "URI: ";
    private static final String PREFIX_VERSION = "Version: ";
    private static final String PREFIX_CHAIN_ID = "Chain ID: ";
    private static final String PREFIX_NONCE = "Nonce: ";
    private static final String PREFIX_ISSUED_AT = "Issued At: ";
    private static final String PREFIX_EXPIRATION = "Expiration Time: ";

    private static final Set<String> VALID_CLUSTER_IDS = Set.of("mainnet", "devnet", "testnet");

    private SiwsMessageParser() {
    }

    /**
     * Parses a SIWS message string into a {@link SiwsMessage}.
     *
     * @throws IllegalArgumentException if the message format is invalid, or if chainId
     *                                  is not one of {mainnet, devnet, testnet}
     */
    public static SiwsMessage parse(String message) {
        if (message == null) {
            throw new IllegalArgumentException("message must not be null");
        }

        String[] lines = message.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            if (lines[i].endsWith("\r")) {
                lines[i] = lines[i].substring(0, lines[i].length() - 1);
            }
        }
        if (lines.length < 10) {
            throw new IllegalArgumentException("expected at least 10 lines, got " + lines.length);
        }

        String domain = parseDomain(lines[0]);
        String address = lines[1];
        if (address.isBlank()) {
            throw new IllegalArgumentException("line 1 (address) must not be blank");
        }

        String uri = null;
        String version = null;
        String chainId = null;
        String nonce = null;
        Instant issuedAt = null;
        Instant expiresAt = null;

        for (int i = 2; i < lines.length; i++) {
            String line = lines[i];
            if (line.startsWith(PREFIX_URI)) {
                uri = extractField(line, PREFIX_URI, i);
            } else if (line.startsWith(PREFIX_VERSION)) {
                version = extractField(line, PREFIX_VERSION, i);
            } else if (line.startsWith(PREFIX_CHAIN_ID)) {
                chainId = extractAndValidateCluster(line, i);
            } else if (line.startsWith(PREFIX_NONCE)) {
                nonce = extractField(line, PREFIX_NONCE, i);
            } else if (line.startsWith(PREFIX_ISSUED_AT)) {
                issuedAt = parseInstant(line, PREFIX_ISSUED_AT, i);
            } else if (line.startsWith(PREFIX_EXPIRATION)) {
                expiresAt = parseInstant(line, PREFIX_EXPIRATION, i);
            }
        }

        if (uri == null) {
            throw new IllegalArgumentException("URI: field is missing");
        }
        if (version == null) {
            throw new IllegalArgumentException("Version: field is missing");
        }
        if (chainId == null) {
            throw new IllegalArgumentException("Chain ID: field is missing");
        }
        if (nonce == null) {
            throw new IllegalArgumentException("Nonce: field is missing");
        }
        if (issuedAt == null) {
            throw new IllegalArgumentException("Issued At: field is missing");
        }
        if (expiresAt == null) {
            throw new IllegalArgumentException("Expiration Time: field is missing");
        }

        return new SiwsMessage(domain, address, uri, version, chainId, nonce, issuedAt, expiresAt);
    }

    private static String parseDomain(String line) {
        if (!line.endsWith(FIRST_LINE_SUFFIX)) {
            throw new IllegalArgumentException(
                    "line 0 must end with \"" + FIRST_LINE_SUFFIX + "\", got: " + line);
        }
        String domain = line.substring(0, line.length() - FIRST_LINE_SUFFIX.length());
        if (domain.isBlank()) {
            throw new IllegalArgumentException("domain extracted from line 0 is blank");
        }
        return domain;
    }

    private static String extractField(String line, String prefix, int index) {
        if (!line.startsWith(prefix)) {
            throw new IllegalArgumentException(
                    "line " + index + " must start with \"" + prefix + "\", got: \"" + line + "\"");
        }
        String value = line.substring(prefix.length());
        if (value.isBlank()) {
            throw new IllegalArgumentException(
                    "line " + index + " value after \"" + prefix + "\" must not be blank");
        }
        return value;
    }

    private static String extractAndValidateCluster(String line, int index) {
        String cluster = extractField(line, PREFIX_CHAIN_ID, index);
        if (!VALID_CLUSTER_IDS.contains(cluster)) {
            throw new IllegalArgumentException(
                    "line " + index + " Chain ID must be one of {mainnet, devnet, testnet}, got: \"" + cluster + "\"");
        }
        return cluster;
    }

    private static Instant parseInstant(String line, String prefix, int index) {
        String raw = extractField(line, prefix, index);
        try {
            return Instant.parse(raw);
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException(
                    "line " + index + " has unparseable timestamp: \"" + raw + "\"", e);
        }
    }
}
