package com.w3auth.backend.identity;

import java.util.regex.Pattern;

/**
 * A CAIP-2 namespace identifying a class of chains.
 *
 * <p>Each constant owns its address and chain-reference validation rules via
 * the two abstract methods below. Any future namespace must consciously
 * implement both — the compiler enforces it.
 */
public enum Namespace {

    EIP155("eip155") {

        private static final Pattern EVM_ADDRESS = Pattern.compile("^0x[0-9a-fA-F]{40}$");
        private static final Pattern DECIMAL_REFERENCE = Pattern.compile("^[0-9]+$");

        @Override
        public String validateAddress(String address) {
            if (address == null || !EVM_ADDRESS.matcher(address).matches()) {
                throw new IllegalArgumentException("Invalid " + this + " address: " + address);
            }
            return address.toLowerCase();
        }

        @Override
        public String validateReference(String reference) {
            if (reference == null || !DECIMAL_REFERENCE.matcher(reference).matches()) {
                throw new IllegalArgumentException(
                        "Invalid chain reference for " + this + ": " + reference);
            }
            return reference;
        }
    },

    SOLANA("solana") {

        // CAIP-2 Solana profile: first 32 chars of the genesis block hash in base58.
        // Valid examples — mainnet: 5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp
        //                  devnet:  EtWTRABZaYq6iMfeYKouRu166VU2xqa1
        private static final Pattern SOLANA_REFERENCE = Pattern.compile("^[1-9A-HJ-NP-Za-km-z]{32}$");

        @Override
        public String validateAddress(String address) {
            if (address == null) {
                throw new IllegalArgumentException("Invalid " + this + " address: null");
            }
            byte[] decoded;
            try {
                decoded = Base58.decode(address);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(
                        "Invalid " + this + " address (not valid base58): " + address, e);
            }
            if (decoded.length != 32) {
                throw new IllegalArgumentException(
                        "Invalid " + this + " address (decoded to "
                                + decoded.length + " bytes, expected 32): " + address);
            }
            // Base58 is case-sensitive; return as-is — do NOT lowercase.
            return address;
        }

        @Override
        public String validateReference(String reference) {
            if (reference == null || !SOLANA_REFERENCE.matcher(reference).matches()) {
                throw new IllegalArgumentException(
                        "Invalid chain reference for " + this + ": " + reference);
            }
            return reference;
        }
    };

    private final String value;

    Namespace(String value) {
        this.value = value;
    }

    /**
     * Validates and canonicalizes {@code address} for this namespace.
     *
     * @return the canonical form (e.g. lowercased for EIP-155; unchanged for Solana)
     * @throws IllegalArgumentException if {@code address} is null or structurally invalid
     */
    public abstract String validateAddress(String address);

    /**
     * Validates the CAIP-2 chain {@code reference} for this namespace.
     *
     * @return the validated reference (unchanged for all current namespaces)
     * @throws IllegalArgumentException if {@code reference} is null or structurally invalid
     */
    public abstract String validateReference(String reference);

    /**
     * The canonical CAIP-2 string form, e.g. {@code "eip155"}.
     */
    public String value() {
        return value;
    }

    /**
     * Parses the canonical CAIP-2 string form.
     *
     * <p>Matching is case-sensitive and exact: the CAIP-2 spec restricts the
     * namespace segment to {@code [-a-z0-9]{3,8}}, i.e. lowercase only.
     * {@code "EIP155"} or {@code "Eip155"} are therefore not the same
     * namespace as {@code "eip155"} and are rejected rather than normalized.
     *
     * @throws IllegalArgumentException if {@code value} is not exactly a supported namespace
     */
    public static Namespace fromString(String value) {
        for (Namespace namespace : values()) {
            if (namespace.value.equals(value)) {
                return namespace;
            }
        }
        throw new IllegalArgumentException("Unsupported namespace: " + value);
    }

    @Override
    public String toString() {
        return value;
    }
}
