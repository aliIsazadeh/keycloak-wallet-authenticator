package com.w3auth.backend.identity;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * A CAIP-10 account id: {@code namespace:reference:address}
 * (e.g. {@code eip155:1:0xabc...}).
 *
 * <p>Construction is the only way to obtain an instance, and construction
 * always validates and canonicalizes — an invalid or non-canonical
 * {@code CaipAccountId} cannot exist. For {@link Namespace#EIP155}, the
 * address is lowercased so that the two EIP-55 case variants of the same
 * address produce equal {@code CaipAccountId}s.
 *
 * <p>The {@code reference} (chain id) is part of the CAIP-10 string and thus
 * part of this value's equality, but per the architecture it is
 * <strong>not</strong> part of the wallet identity key — see
 * {@link #identityKey()}.
 */
public final class CaipAccountId {

    private static final Pattern EVM_ADDRESS = Pattern.compile("^0x[0-9a-fA-F]{40}$");
    private static final Pattern DECIMAL_REFERENCE = Pattern.compile("^[0-9]+$");

    private final Namespace namespace;
    private final String reference;
    private final String address;

    private CaipAccountId(Namespace namespace, String reference, String address) {
        this.namespace = namespace;
        this.reference = reference;
        this.address = address;
    }

    /**
     * Parses a CAIP-10 string of the form {@code namespace:reference:address}.
     *
     * @throws IllegalArgumentException if the format is invalid, the namespace
     *         is unsupported, or the reference/address fail validation
     */
    public static CaipAccountId parse(String caipAccountId) {
        if (caipAccountId == null) {
            throw new IllegalArgumentException("CAIP-10 account id must not be null");
        }
        String[] parts = caipAccountId.split(":", -1);
        if (parts.length != 3) {
            throw new IllegalArgumentException(
                    "CAIP-10 account id must have exactly 3 colon-separated parts (namespace:reference:address): "
                            + caipAccountId);
        }
        return of(Namespace.fromString(parts[0]), parts[1], parts[2]);
    }

    /**
     * Builds a {@code CaipAccountId} from its parts, validating and
     * canonicalizing the address according to {@code namespace}.
     *
     * @throws IllegalArgumentException if {@code reference} or {@code address}
     *         fail validation for {@code namespace}
     */
    public static CaipAccountId of(Namespace namespace, String reference, String address) {
        Objects.requireNonNull(namespace, "namespace must not be null");
        if (reference == null || !DECIMAL_REFERENCE.matcher(reference).matches()) {
            throw new IllegalArgumentException("Invalid chain reference for " + namespace + ": " + reference);
        }
        if (address == null || !EVM_ADDRESS.matcher(address).matches()) {
            throw new IllegalArgumentException("Invalid " + namespace + " address: " + address);
        }
        return new CaipAccountId(namespace, reference, address.toLowerCase());
    }

    public Namespace namespace() {
        return namespace;
    }

    /**
     * The CAIP-2 chain reference, e.g. {@code "1"} for Ethereum mainnet.
     * Session/auth context, not part of the wallet identity key.
     */
    public String reference() {
        return reference;
    }

    /**
     * The canonical (lowercase) address.
     */
    public String address() {
        return address;
    }

    /**
     * The wallet identity key: {@code (namespace, address)}, per the rule that
     * the address is identity and the chain reference is session context.
     */
    public IdentityKey identityKey() {
        return new IdentityKey(namespace, address);
    }

    /**
     * The canonical CAIP-10 string: {@code namespace:reference:address}.
     */
    @Override
    public String toString() {
        return namespace + ":" + reference + ":" + address;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof CaipAccountId other)) {
            return false;
        }
        return namespace == other.namespace
                && reference.equals(other.reference)
                && address.equals(other.address);
    }

    @Override
    public int hashCode() {
        return Objects.hash(namespace, reference, address);
    }

    /**
     * The unique key for a wallet identity: {@code (namespace, address)}.
     * ChainId/reference is deliberately excluded — the same EVM key works on
     * every EVM chain, so it must not split one wallet into many identities.
     */
    public record IdentityKey(Namespace namespace, String address) {

        /**
         * The canonical JWT subject for this identity: {@code namespace:address}
         * (two-part, no chainId). Single authoritative definition — callers must
         * not concatenate these fields themselves.
         */
        public String toJwtSubject() {
            return namespace.value() + ":" + address;
        }
    }
}
