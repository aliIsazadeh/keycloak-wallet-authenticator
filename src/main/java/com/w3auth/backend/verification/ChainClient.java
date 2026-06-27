package com.w3auth.backend.verification;

/**
 * Port for reading on-chain state needed to verify smart-contract wallets (EIP-1271).
 * Core — no Spring, no web3j imports.
 *
 * <p>Implementations must distinguish three outcomes for
 * {@link #isValidErc1271Signature}:
 * <ul>
 *   <li>The contract returned the EIP-1271 magic value {@code 0x1626ba7e} → {@code true}</li>
 *   <li>The contract returned any other value, or reverted → {@code false}
 *       (authenticated-no; the node responded, but the contract rejected the signature)</li>
 *   <li>The node was unreachable or returned an unexpected RPC error → throw
 *       {@link RuntimeException} (transport failure must not look like authenticated-no)</li>
 * </ul>
 *
 * <p>Implementations must satisfy the same three-outcome contract for
 * {@link #isValidSignatureDeployless}: magic returned → {@code true};
 * non-magic or revert → {@code false}; transport/RPC error → throw.
 */
public interface ChainClient {

    /**
     * Returns the deployed bytecode hex string for {@code address} (e.g. {@code "0x6080..."})
     * or {@code "0x"} when the address holds no code (EOA or undeployed address).
     *
     * @throws RuntimeException on transport or RPC error
     */
    String getCode(String address);

    /**
     * Calls {@code isValidSignature(bytes32,bytes)} on {@code contractAddress} and returns
     * {@code true} only if the contract returns the EIP-1271 magic value {@code 0x1626ba7e}.
     *
     * <p>A non-magic return value or a revert is authentication-failed ({@code false}).
     * A transport/IO or RPC error throws — "call failed" must never look like "authenticated-no".
     *
     * @param contractAddress the ERC-1271 contract to query
     * @param hash            the 32-byte message hash that was signed
     * @param signature       the signature bytes to validate
     * @throws RuntimeException on transport or RPC error
     */
    boolean isValidErc1271Signature(String contractAddress, byte[] hash, byte[] signature);

    /**
     * Validates an EIP-6492-wrapped signature using a deployless universal verifier.
     * The full wrapped signature (including the 32-byte EIP-6492 magic suffix) is passed;
     * the implementation is responsible for executing the factory call and validating the
     * inner signature without requiring the contract wallet to be pre-deployed.
     *
     * <p>Same three-outcome contract as {@link #isValidErc1271Signature}:
     * magic returned → {@code true}; non-magic or revert → {@code false};
     * transport/RPC error → throw {@link RuntimeException}.
     *
     * @param signer    claimed contract wallet address (canonical lowercase hex, same convention
     *                  as {@link #isValidErc1271Signature})
     * @param hash      32-byte EIP-191 message digest (same value computed by the dispatcher
     *                  via {@code Sign.getEthereumMessageHash})
     * @param signature the full EIP-6492-wrapped signature bytes (body + 32-byte magic suffix)
     * @throws RuntimeException on transport or RPC error
     */
    boolean isValidSignatureDeployless(String signer, byte[] hash, byte[] signature);
}
