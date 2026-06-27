package com.w3auth.backend.verification;

/**
 * Structural decoder and well-formedness gate for EIP-6492 counterfactual signature envelopes.
 *
 * <p>An EIP-6492 envelope is structured as:
 * {@code abi.encode(address factory, bytes factoryCalldata, bytes innerSig) || magicSuffix32}
 * where the 32-byte magic suffix is {@code 0x6492...6492} (the pattern repeated 16 times).
 *
 * <p>{@link #validateStructure} confirms the body (everything before the magic suffix) is a
 * well-formed ABI encoding of {@code (address, bytes, bytes)}. The decoded components are
 * validated then <em>discarded</em> — the caller passes the full wrapped signature to the chain.
 * The on-chain universal verifier handles factory dispatch and inner-sig verification.
 *
 * <p>Design contract: throw {@link VerificationException} on any structural failure so
 * the chain is never called with a malformed envelope. Never silently coerce bad input.
 */
final class Eip6492Envelope {

    private Eip6492Envelope() {}

    /**
     * Validates that {@code sigBytes} (the full EIP-6492 signature, including the trailing
     * 32-byte magic suffix already confirmed by the caller) is structurally well-formed.
     *
     * <p>Checks:
     * <ul>
     *   <li>Body length (total minus 32-byte suffix) &ge; 96 bytes — the minimum for a
     *       3-word ABI head: factory address + two dynamic offsets.
     *   <li>Offset words for {@code factoryCalldata} and {@code innerSig} are in-bounds
     *       and point past the head (offset &ge; 96).
     *   <li>Length prefixes for both dynamic fields do not overrun the body.
     * </ul>
     *
     * @param sigBytes the full EIP-6492-wrapped signature bytes (caller has confirmed the
     *                 trailing 32-byte magic suffix is present)
     * @throws VerificationException on any structural failure
     */
    static void validateStructure(byte[] sigBytes) throws VerificationException {
        // Body = everything except the trailing 32-byte magic suffix.
        // ABI head for (address, bytes, bytes): 3 words × 32 bytes = 96 bytes minimum.
        //   word 0: factory address (static, 32 bytes)
        //   word 1: offset to factoryCalldata tail
        //   word 2: offset to innerSig tail
        int bodyLen = sigBytes.length - 32;
        if (bodyLen < 96) {
            throw new VerificationException(
                    "malformed EIP-6492 envelope: body too short ("
                    + bodyLen + " bytes, minimum 96)");
        }

        // Word 1 (bytes 32–63): ABI offset to factoryCalldata tail.
        int offsetCalldata = readOffset(sigBytes, 32, bodyLen, "factoryCalldata");

        // Word 2 (bytes 64–95): ABI offset to innerSig tail.
        int offsetInnerSig = readOffset(sigBytes, 64, bodyLen, "innerSig");

        // Validate length prefix and data extent for each dynamic field.
        validateDynamicField(sigBytes, offsetCalldata, bodyLen, "factoryCalldata");
        validateDynamicField(sigBytes, offsetInnerSig, bodyLen, "innerSig");
    }

    /**
     * Reads a 32-byte ABI offset word from {@code body[wordPos..wordPos+31]}.
     * The high 28 bytes must be zero and the resulting int must be in [96, bodyLen).
     */
    private static int readOffset(byte[] body, int wordPos, int bodyLen, String field)
            throws VerificationException {
        if (wordPos + 32 > bodyLen) {
            throw new VerificationException(
                    "malformed EIP-6492 envelope: head word for " + field
                    + " at position " + wordPos + " overruns body");
        }
        // Reject offsets that would not fit in a Java int (high 28 bytes non-zero).
        for (int i = wordPos; i < wordPos + 28; i++) {
            if (body[i] != 0) {
                throw new VerificationException(
                        "malformed EIP-6492 envelope: " + field
                        + " offset exceeds addressable range");
            }
        }
        int offset = ((body[wordPos + 28] & 0xFF) << 24)
                   | ((body[wordPos + 29] & 0xFF) << 16)
                   | ((body[wordPos + 30] & 0xFF) << 8)
                   |  (body[wordPos + 31] & 0xFF);
        // Offset must point into the tail section (past the 96-byte head).
        if (offset < 96 || offset >= bodyLen) {
            throw new VerificationException(
                    "malformed EIP-6492 envelope: " + field + " offset " + offset
                    + " out of range [96, " + bodyLen + ")");
        }
        return offset;
    }

    /**
     * Validates the length-prefixed dynamic field whose tail begins at {@code body[offset]}.
     * Checks that the 32-byte length word and the declared number of data bytes all fit
     * within the body.
     */
    private static void validateDynamicField(byte[] body, int offset, int bodyLen, String field)
            throws VerificationException {
        if (offset + 32 > bodyLen) {
            throw new VerificationException(
                    "malformed EIP-6492 envelope: " + field
                    + " length word at offset " + offset + " overruns body");
        }
        // High 28 bytes of length must be zero.
        for (int i = offset; i < offset + 28; i++) {
            if (body[i] != 0) {
                throw new VerificationException(
                        "malformed EIP-6492 envelope: " + field
                        + " declared length exceeds addressable range");
            }
        }
        int length = ((body[offset + 28] & 0xFF) << 24)
                   | ((body[offset + 29] & 0xFF) << 16)
                   | ((body[offset + 30] & 0xFF) << 8)
                   |  (body[offset + 31] & 0xFF);
        if (offset + 32 + length > bodyLen) {
            throw new VerificationException(
                    "malformed EIP-6492 envelope: " + field
                    + " data overruns body (offset=" + offset
                    + ", length=" + length + ", bodyLen=" + bodyLen + ")");
        }
    }
}
