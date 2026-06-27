package com.w3auth.backend.verification;

import org.web3j.crypto.Sign;

import java.nio.charset.StandardCharsets;

/**
 * Dispatcher that routes each verify request to either the EOA path (ecrecover) or the
 * EIP-1271 path (on-chain {@code isValidSignature}), based on whether the claimed address
 * holds deployed bytecode.
 *
 * <p>Dispatch order — applied in this exact sequence:
 * <ol>
 *   <li><b>EIP-6492 suffix check</b> — if the last 32 bytes of the decoded signature equal
 *       the magic trailer {@code 0x6492...6492}, validate the envelope structure (via
 *       {@link Eip6492Envelope#validateStructure}) then delegate to
 *       {@link ChainClient#isValidSignatureDeployless}. The check <em>must</em> precede
 *       {@code getCode} because a 6492-wrapped signature can target an address that already
 *       has code; routing by code first would misroute the deployed-but-still-wrapped case.
 *   <li><b>eth_getCode</b> on the claimed address — empty result → EOA; non-empty → contract.
 *   <li><b>EOA path</b> — full delegation to {@code eoaVerifier} (ecrecover).
 *       The caller's step-5 signer-equals-claim check still guards this path.
 *   <li><b>EIP-1271 contract path</b> — compute the EIP-191-prefixed Keccak-256 hash of the
 *       raw message, call {@code isValidSignature} on-chain. On success, return a
 *       {@link VerifiedIdentity} whose {@code signerAddress} equals the claimed contract
 *       address, so the caller's step-5 {@code equalsIgnoreCase} check passes by construction.
 *       The real gate is the on-chain {@code isValidSignature} returning the magic value.
 * </ol>
 *
 * <p>The hash passed to {@code isValidSignature} is computed via
 * {@code Sign.getEthereumMessageHash} — byte-identical to the hash the EOA path signs over.
 * Correctness against a real on-chain contract is verified in Commit 3, not here.
 */
public class ContractAwareSignatureVerifier implements SignatureVerifier {

    // EIP-6492 magic suffix: last 32 bytes of a wrapped signature.
    // Pattern 0x6492 repeated 16 times. Source: https://eips.ethereum.org/EIPS/eip-6492
    private static final byte[] EIP6492_MAGIC_SUFFIX = hexConstantToBytes(
            "6492649264926492649264926492649264926492649264926492649264926492");

    private final SignatureVerifier eoaVerifier;
    private final ChainClient chainClient;

    public ContractAwareSignatureVerifier(SignatureVerifier eoaVerifier, ChainClient chainClient) {
        this.eoaVerifier = eoaVerifier;
        this.chainClient = chainClient;
    }

    @Override
    public VerifiedIdentity verify(VerificationRequest request) throws VerificationException {
        // Step a: hex-decode before anything else — reject malformed input immediately.
        byte[] sigBytes = decodeSignatureHex(request.signature());

        // Step b: EIP-6492 suffix check — must precede getCode (see class Javadoc).
        if (hasEip6492Suffix(sigBytes)) {
            // Well-formedness gate: validate ABI structure before touching the chain.
            // Throws VerificationException on malformed input; the chain is never called.
            Eip6492Envelope.validateStructure(sigBytes);

            // Same EIP-191 hash used on all other paths — the universal validator on-chain
            // applies the same ecrecover internally.
            byte[] hash6492 = Sign.getEthereumMessageHash(
                    request.rawMessage().getBytes(StandardCharsets.UTF_8));
            String signer = request.message().address();

            boolean ok6492;
            try {
                ok6492 = chainClient.isValidSignatureDeployless(signer, hash6492, sigBytes);
            } catch (RuntimeException e) {
                throw new VerificationException(
                        "ChainClient transport error during EIP-6492 validation: "
                        + e.getMessage(), e);
            }
            if (!ok6492) {
                throw new VerificationException("EIP-6492 validation failed");
            }
            // Contract-wallet identity = the claimed address; same convention as EIP-1271.
            return new VerifiedIdentity(signer);
        }

        // Step c: determine whether the claimed address holds deployed code.
        String code = chainClient.getCode(request.message().address());
        if (isCodeEmpty(code)) {
            // Step d: EOA path — delegate fully; ecrecover and step-5 address check handled by caller.
            return eoaVerifier.verify(request);
        }

        // Step e: EIP-1271 contract path.
        // This hash is byte-identical to what the EOA path signs over — Sign.signedPrefixedMessageToKey
        // applies the same EIP-191 prefix internally.
        byte[] hash = Sign.getEthereumMessageHash(
                request.rawMessage().getBytes(StandardCharsets.UTF_8));

        boolean ok;
        try {
            ok = chainClient.isValidErc1271Signature(
                    request.message().address(), hash, sigBytes);
        } catch (RuntimeException e) {
            // Transport/RPC failure must NOT look like "authentication failed" — propagate
            // as VerificationException so the caller has a single checked type to handle,
            // but the cause is preserved and the message makes the transport origin clear.
            throw new VerificationException(
                    "ChainClient transport error during ERC-1271 validation: " + e.getMessage(), e);
        }

        if (!ok) {
            // Explicitly reject — never fall through to returning an identity on false.
            throw new VerificationException("ERC-1271 validation failed");
        }

        // Contract identity = the claimed address (the EIP-1271 call was on that address).
        // The caller's step-5 equalsIgnoreCase(parsed.address()) passes by construction;
        // the real authentication gate is ok == true above.
        return new VerifiedIdentity(request.message().address());
    }

    /**
     * Returns {@code true} if {@code getCode} result means no deployed code.
     * Normalizes by stripping "0x" prefix, then treats blank or all-zero hex as empty.
     * Covers "0x", "0x0", "", and null — all valid "no code" responses from nodes.
     */
    static boolean isCodeEmpty(String code) {
        if (code == null || code.isEmpty()) return true;
        String hex = (code.startsWith("0x") || code.startsWith("0X")) ? code.substring(2) : code;
        if (hex.isBlank()) return true;
        for (char c : hex.toCharArray()) {
            if (c != '0') return false;
        }
        return true;
    }

    private static boolean hasEip6492Suffix(byte[] sig) {
        if (sig.length < 32) return false;
        int offset = sig.length - 32;
        for (int i = 0; i < 32; i++) {
            if (sig[offset + i] != EIP6492_MAGIC_SUFFIX[i]) return false;
        }
        return true;
    }

    /**
     * Hex-decodes the signature string to raw bytes. Accepts an optional "0x"/"0X" prefix.
     * Rejects non-hex characters explicitly — web3j's {@code Numeric.hexStringToByteArray}
     * silently coerces invalid chars, producing garbage bytes rather than throwing.
     *
     * @throws VerificationException on empty, odd-length, or non-hex input
     */
    private static byte[] decodeSignatureHex(String hex) throws VerificationException {
        String clean = (hex.startsWith("0x") || hex.startsWith("0X")) ? hex.substring(2) : hex;
        if (clean.isEmpty()) {
            throw new VerificationException("signature hex must not be empty");
        }
        if (clean.length() % 2 != 0) {
            throw new VerificationException("signature hex has odd length: " + clean.length() + " chars");
        }
        for (int i = 0; i < clean.length(); i++) {
            if (Character.digit(clean.charAt(i), 16) == -1) {
                throw new VerificationException(
                        "signature contains non-hex character '" + clean.charAt(i)
                        + "' at position " + i);
            }
        }
        byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static byte[] hexConstantToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
