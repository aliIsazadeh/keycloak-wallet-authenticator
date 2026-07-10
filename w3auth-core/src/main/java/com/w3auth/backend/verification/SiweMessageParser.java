package com.w3auth.backend.verification;

import java.time.Instant;
import java.time.format.DateTimeParseException;

/**
 * Parses the EIP-4361 (Sign-In with Ethereum) message string. Spec-tolerant:
 * accepts both the no-statement form and the optional {@code statement} block
 * defined by EIP-4361 ABNF. Required fields (URI, Version, Chain ID, Nonce,
 * Issued At, Expiration Time) are located by their label prefix rather than fixed
 * line indices, so unknown or optional trailing fields are silently ignored.
 *
 * <p>Fail-closed: missing or malformed required fields throw
 * {@link IllegalArgumentException}. Policy validation (domain match, nonce
 * expiry, chainId check) and signature verification are the caller's
 * responsibility.
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
     * <p>Supports both the no-statement (10-line) and optional-statement (11+ line)
     * EIP-4361 layouts. All required fields must be present.
     *
     * @throws IllegalArgumentException if the message is structurally invalid or
     *                                  any required field is missing
     */
    public static SiweMessage parse(String message) {
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

        requireBlankLine(lines[2], 2);

        // EIP-4361: optional statement sits between the two blank lines that follow the address.
        // No statement: line 3 is blank → field block starts at line 4.
        // Statement:    line 3 is the statement text → line 4 must be blank → field block starts at line 5.
        int fieldStart;
        if (lines[3].isEmpty()) {
            fieldStart = 4;
        } else {
            if (lines.length < 11) {
                throw new IllegalArgumentException(
                        "expected at least 11 lines when statement is present, got " + lines.length);
            }
            requireBlankLine(lines[4], 4);
            fieldStart = 5;
        }

        String uri = null;
        String version = null;
        String chainId = null;
        String nonce = null;
        Instant issuedAt = null;
        Instant expiresAt = null;

        for (int i = fieldStart; i < lines.length; i++) {
            String line = lines[i];
            if (line.startsWith(PREFIX_URI)) {
                uri = extractField(line, PREFIX_URI, i);
            } else if (line.startsWith(PREFIX_VERSION)) {
                version = extractField(line, PREFIX_VERSION, i);
            } else if (line.startsWith(PREFIX_CHAIN_ID)) {
                chainId = extractField(line, PREFIX_CHAIN_ID, i);
            } else if (line.startsWith(PREFIX_NONCE)) {
                nonce = extractField(line, PREFIX_NONCE, i);
            } else if (line.startsWith(PREFIX_ISSUED_AT)) {
                issuedAt = parseInstant(line, PREFIX_ISSUED_AT, i);
            } else if (line.startsWith(PREFIX_EXPIRATION)) {
                expiresAt = parseInstant(line, PREFIX_EXPIRATION, i);
            }
        }

        if (uri == null) throw new IllegalArgumentException("URI: field is missing");
        if (version == null) throw new IllegalArgumentException("Version: field is missing");
        if (chainId == null) throw new IllegalArgumentException("Chain ID: field is missing");
        if (nonce == null) throw new IllegalArgumentException("Nonce: field is missing");
        if (issuedAt == null) throw new IllegalArgumentException("Issued At: field is missing");
        if (expiresAt == null) throw new IllegalArgumentException("Expiration Time: field is missing");

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
