package com.w3auth.backend.verification;

import org.junit.jupiter.api.Test;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EthereumSignatureVerifierTest {

    // Hardhat/Anvil default account #0.
    // Private key is published in the Hardhat docs (https://hardhat.org/hardhat-network/docs/reference)
    // and is used as a standard test key throughout the Ethereum tooling ecosystem.
    // The expected address (0xf39Fd6...) is the publicly documented address for this key —
    // it is the external, independently-known anchor that makes the known-good test meaningful.
    // If EthereumSignatureVerifier has a bug in prefix handling or recovery, ecrecover will
    // return a random-looking address rather than 0xf39Fd6..., and the test fails.
    private static final String HARDHAT_PRIVATE_KEY =
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    private static final String HARDHAT_ADDRESS =
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"; // lowercase for comparison

    // External cross-tool vector: signed with ethers.js v6 signMessage (NOT web3j).
    // Proves cross-library agreement on the EIP-191 prefix scheme.
    // If EthereumSignatureVerifier has a prefix bug, web3j and ethers.js would
    // apply different hashes and recovery would return a wrong address.
    private static final String ETHERS_MESSAGE = "W3-Auth test vector";
    private static final String ETHERS_SIGNATURE =
            "0xc416b87d1c37724e9f187159672d0c0ab2810bb208bd0f25d3577b44ce0269f9" +
            "52b07909c52bcb1b4a2a8ea4f10bcefcfbf4908d95563698284f726ae9343de01c";

    // web3j round-trip uses a different message to avoid ambiguity with the ethers vector
    private static final String WEB3J_MESSAGE = "Hello, EthereumSignatureVerifier!";

    private final EthereumSignatureVerifier verifier = new EthereumSignatureVerifier();

    // ── primary cross-tool vector (ethers.js v6) ──────────────────────────────

    @Test
    void verify_ethersJsVector_recoversPublishedAddress() throws VerificationException {
        // Signature produced by ethers.js v6 wallet.signMessage(ETHERS_MESSAGE) with
        // Hardhat account #0. This is the primary correctness anchor: recovery must agree
        // with a tool that is independent of web3j. A shared EIP-191 prefix bug would
        // not cancel out here — web3j would recover a different address than 0xf39Fd6...
        VerifiedIdentity result = verifier.verify(request(ETHERS_MESSAGE, ETHERS_SIGNATURE));

        assertThat(result.signerAddress()).isEqualToIgnoringCase(HARDHAT_ADDRESS);
    }

    // ── web3j round-trip (self-consistency check) ─────────────────────────────

    @Test
    void verify_web3jRoundTrip_selfConsistent() throws VerificationException {
        // Signs and recovers both via web3j — a shared prefix bug would cancel out.
        // Kept as a regression guard against code changes, but the ethers vector above
        // is the primary cross-tool correctness anchor.
        ECKeyPair keyPair = ECKeyPair.create(Numeric.hexStringToByteArray(HARDHAT_PRIVATE_KEY));
        Sign.SignatureData sigData =
                Sign.signPrefixedMessage(WEB3J_MESSAGE.getBytes(StandardCharsets.UTF_8), keyPair);

        VerifiedIdentity result = verifier.verify(request(WEB3J_MESSAGE, signatureDataToHex(sigData)));

        assertThat(result.signerAddress()).isEqualToIgnoringCase(HARDHAT_ADDRESS);
    }

    // ── v normalisation: {0,1} → {27,28} ─────────────────────────────────────

    @Test
    void verify_vZeroOrOne_normalisedAndRecovered() throws VerificationException {
        ECKeyPair keyPair = ECKeyPair.create(Numeric.hexStringToByteArray(HARDHAT_PRIVATE_KEY));
        Sign.SignatureData sigData =
                Sign.signPrefixedMessage(WEB3J_MESSAGE.getBytes(StandardCharsets.UTF_8), keyPair);

        // web3j signing produces v ∈ {27,28}; subtract 27 to simulate a wallet returning v ∈ {0,1}
        byte originalV = sigData.getV()[0];
        byte rawV = (byte) (originalV - 27); // 27→0 or 28→1

        byte[] bytes = concatSignatureBytes(sigData);
        bytes[64] = rawV;
        String hexSig = "0x" + Numeric.toHexStringNoPrefix(bytes);

        VerifiedIdentity result = verifier.verify(request(WEB3J_MESSAGE, hexSig));

        assertThat(result.signerAddress()).isEqualToIgnoringCase(HARDHAT_ADDRESS);
    }

    // ── tampered message ──────────────────────────────────────────────────────

    @Test
    void verify_tamperedMessage_recoversDifferentAddress() throws VerificationException {
        // Sign WEB3J_MESSAGE; verify against a tampered version. ecrecover is deterministic —
        // a one-byte change in the message produces a completely different hash, so the
        // recovered address will not equal HARDHAT_ADDRESS. We assert it differs rather
        // than throws, because ecrecover on a mismatched message is not an error; it just
        // returns the wrong key. The signer-vs-claim check in VerifyAndAuthenticate catches this.
        ECKeyPair keyPair = ECKeyPair.create(Numeric.hexStringToByteArray(HARDHAT_PRIVATE_KEY));
        Sign.SignatureData sigData =
                Sign.signPrefixedMessage(WEB3J_MESSAGE.getBytes(StandardCharsets.UTF_8), keyPair);
        String hexSig = signatureDataToHex(sigData);

        String tamperedMessage = WEB3J_MESSAGE + "!"; // one character appended

        VerifiedIdentity result = verifier.verify(request(tamperedMessage, hexSig));

        assertThat(result.signerAddress()).isNotEqualToIgnoringCase(HARDHAT_ADDRESS);
    }

    // ── malformed signatures — fail closed ────────────────────────────────────

    @Test
    void verify_wrongLengthSignature_throws() {
        // 64 bytes (128 hex chars) instead of 65 — missing the v byte
        String shortSig = "0x" + "ab".repeat(64);

        assertThatThrownBy(() -> verifier.verify(request(WEB3J_MESSAGE, shortSig)))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("65 bytes");
    }

    @Test
    void verify_nonHexSignature_throws() {
        // 130 chars but not valid hex (contains 'z')
        String garbage = "0x" + "z".repeat(128) + "1b";

        assertThatThrownBy(() -> verifier.verify(request(WEB3J_MESSAGE, garbage)))
                .isInstanceOf(VerificationException.class);
    }

    @Test
    void verify_invalidRecoveryByte_throws() {
        // Take a valid 65-byte signature and flip v to 0x02 — out of range for web3j
        // (which requires v ∈ [27,34] after normalisation). This exercises the SignatureException
        // catch in EthereumSignatureVerifier and ensures we fail closed.
        ECKeyPair keyPair = ECKeyPair.create(Numeric.hexStringToByteArray(HARDHAT_PRIVATE_KEY));
        Sign.SignatureData sigData =
                Sign.signPrefixedMessage(WEB3J_MESSAGE.getBytes(StandardCharsets.UTF_8), keyPair);

        byte[] bytes = concatSignatureBytes(sigData);
        bytes[64] = 0x02; // invalid: neither 0/1 (raw) nor 27/28 (legacy), so stays as 2 after our check

        String invalidSig = "0x" + Numeric.toHexStringNoPrefix(bytes);

        assertThatThrownBy(() -> verifier.verify(request(WEB3J_MESSAGE, invalidSig)))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("recovery failed");
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static VerificationRequest request(String rawMessage, String signature) {
        // SiweMessage is not used by EthereumSignatureVerifier (it only needs rawMessage
        // and signature). A minimal valid instance satisfies the record's non-null guard.
        SiweMessage dummy = new SiweMessage(
                "example.com",
                "0xf39fd6e51aad88f6f4ce6ab8827279cffFb92266",
                "https://example.com",
                "1",
                "1",
                "testNonce",
                Instant.parse("2026-06-15T12:00:00Z"),
                Instant.parse("2026-06-15T12:05:00Z"));
        return new VerificationRequest(dummy, rawMessage, signature);
    }

    private static byte[] concatSignatureBytes(Sign.SignatureData sigData) {
        byte[] bytes = new byte[65];
        System.arraycopy(sigData.getR(), 0, bytes, 0, 32);
        System.arraycopy(sigData.getS(), 0, bytes, 32, 32);
        bytes[64] = sigData.getV()[0];
        return bytes;
    }

    private static String signatureDataToHex(Sign.SignatureData sigData) {
        return "0x" + Numeric.toHexStringNoPrefix(concatSignatureBytes(sigData));
    }
}
