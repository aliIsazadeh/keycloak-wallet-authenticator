package com.w3auth.backend.verification;

import java.time.Instant;
import java.time.format.DateTimeParseException;

/**
 * Parses the EIP-4361 message string produced by
 * {@code challenge.SiweMessageFactory}. Strict and fail-closed: any deviation
 * from the expected 10-line layout throws {@link IllegalArgumentException}.
 *
 * <p>This parser is intentionally narrow — it only accepts messages in the
 * exact format this server emits (no statement block, no optional fields beyond
 * what the factory produces). Policy validation (domain match, nonce expiry,
 * chainId check) and signature verification are the caller's responsibility.
 */
public final class SiweMessageParser {

    private static final String FIRST_LINE_SUFFIX = " wants you to sign in with your Ethereum account:";
    private static final String PREFIX_URI = "URI: ";
    private static final String PREFIX_VERSION = "Version: ";
    private static final String PREFIX_CHAIN_ID = "Chain ID: ";
    private static final String PREFIX_NONCE = "Nonce: ";
    private static final String PREFIX_ISSUED_AT = "Issued At: ";
    private static final String PREFIX_EXPIRATION = "Expiration Time: ";

    private SiweMessageParser() {
    }

    /**
     * Parses a SIWE message string into a {@link SiweMessage}.
     *
     * @throws IllegalArgumentException if the message does not exactly match
     *                                  the expected 10-line EIP-4361 layout
     */
    public static SiweMessage parse(String message) {
        if (message == null) {
            throw new IllegalArgumentException("message must not be null");
        }

        String[] lines = message.split("\n", -1);
        if (lines.length != 10) {
            throw new IllegalArgumentException(
                    "expected 10 lines, got " + lines.length);
        }

        String domain = parseDomain(lines[0]);
        String address = lines[1];
        if (address.isBlank()) {
            throw new IllegalArgumentException("line 1 (address) must not be blank");
        }

        requireBlankLine(lines[2], 2);
        requireBlankLine(lines[3], 3);

        String uri = extractField(lines[4], PREFIX_URI, 4);
        String version = extractField(lines[5], PREFIX_VERSION, 5);
        String chainId = extractField(lines[6], PREFIX_CHAIN_ID, 6);
        String nonce = extractField(lines[7], PREFIX_NONCE, 7);
        Instant issuedAt = parseInstant(lines[8], PREFIX_ISSUED_AT, 8);
        Instant expiresAt = parseInstant(lines[9], PREFIX_EXPIRATION, 9);

        return new SiweMessage(domain, address, uri, version, chainId, nonce, issuedAt, expiresAt);
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

    private static void requireBlankLine(String line, int index) {
        if (!line.isEmpty()) {
            throw new IllegalArgumentException(
                    "line " + index + " must be blank, got: \"" + line + "\"");
        }
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
