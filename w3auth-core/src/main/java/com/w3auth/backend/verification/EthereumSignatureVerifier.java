package com.w3auth.backend.verification;

import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.util.Arrays;

/**
 * EOA signature verifier for EIP-4361 (SIWE). Applies the EIP-191 personal-sign
 * prefix, Keccak-256 hashes, and recovers the signer via secp256k1 ecrecover.
 *
 * <p>This class only recovers the signer address from the signature. It does
 * NOT compare the result against the address claim in the SIWE message — that
 * responsibility belongs to {@code VerifyAndAuthenticate} (separation of concerns:
 * crypto recovery vs. auth logic).
 *
 * <p>Depends on {@code org.web3j:crypto} (Bouncy Castle secp256k1 + Keccak).
 * No web3j RPC or networking code is involved.
 */
public class EthereumSignatureVerifier implements SignatureVerifier {

    @Override
    public VerifiedIdentity verify(VerificationRequest request) throws VerificationException {
        byte[] sigBytes = decodeSignature(request.signature());

        // r: bytes 0-31, s: bytes 32-63, v: byte 64
        byte[] r = Arrays.copyOfRange(sigBytes, 0, 32);
        byte[] s = Arrays.copyOfRange(sigBytes, 32, 64);
        byte v = sigBytes[64];

        // Normalize v: wallets may return {0,1} (raw recId) or {27,28} (EIP-155 legacy).
        // web3j expects v >= 27; it computes recId = v - 27 internally.
        if (v == 0 || v == 1) {
            v = (byte) (v + 27);
        }

        Sign.SignatureData sigData = new Sign.SignatureData(new byte[]{v}, r, s);

        byte[] msgBytes = request.rawMessage().getBytes(StandardCharsets.UTF_8);
        BigInteger publicKey;
        try {
            // Applies "Ethereum Signed Message:\n{byteLen}" prefix, Keccak-256 hashes,
            // and recovers the public key. Throws SignatureException if v is out of range
            // [27,34] or if the recovered point is not on the curve.
            publicKey = Sign.signedPrefixedMessageToKey(msgBytes, sigData);
        } catch (SignatureException e) {
            throw new VerificationException("signature recovery failed: " + e.getMessage(), e);
        }

        // Keys.getAddress returns the last 20 bytes of the Keccak-256 hash of the
        // public key, as a lowercase hex string without the 0x prefix.
        String address = "0x" + Keys.getAddress(publicKey);
        return new VerifiedIdentity(address);
    }

    /**
     * Decodes a hex-encoded signature to exactly 65 raw bytes.
     * Accepts signatures with or without a {@code 0x} prefix.
     *
     * @throws VerificationException if the string is not 65 bytes of valid hex
     */
    private static byte[] decodeSignature(String hex) throws VerificationException {
        String clean = (hex.startsWith("0x") || hex.startsWith("0X"))
                ? hex.substring(2) : hex;
        if (clean.length() != 130) {
            throw new VerificationException(
                    "signature must be 65 bytes (130 hex chars without 0x), got "
                    + clean.length() / 2 + " bytes (" + clean.length() + " hex chars)");
        }
        // Numeric.hexStringToByteArray silently coerces non-hex chars via Character.digit,
        // returning -1 and producing garbage bytes rather than throwing. Validate explicitly.
        for (int i = 0; i < clean.length(); i++) {
            if (Character.digit(clean.charAt(i), 16) == -1) {
                throw new VerificationException(
                        "signature contains non-hex character '" + clean.charAt(i)
                        + "' at position " + i);
            }
        }
        return Numeric.hexStringToByteArray(clean);
    }
}
