package com.w3auth.backend.identity;

/**
 * A CAIP-2 namespace identifying a class of chains.
 *
 * <p>V1 supports only {@link #EIP155} (EVM chains). Adding a second namespace
 * (e.g. Solana) is deferred to M4.
 */
public enum Namespace {

    EIP155("eip155");

    private final String value;

    Namespace(String value) {
        this.value = value;
    }

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
     * namespace as {@code "eip155"} and are rejected rather than normalized —
     * an account id is either canonical CAIP-2 on the wire, or it is invalid.
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
