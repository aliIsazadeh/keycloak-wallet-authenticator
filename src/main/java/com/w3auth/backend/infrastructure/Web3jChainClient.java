package com.w3auth.backend.infrastructure;

import com.w3auth.backend.verification.ChainClient;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.Transaction;

import java.io.IOException;
import java.util.HexFormat;

public class Web3jChainClient implements ChainClient {

    private final Web3j web3j;

    public Web3jChainClient(Web3j web3j) {
        this.web3j = web3j;
    }

    @Override
    public String getCode(String address) {
        try {
            var response = web3j.ethGetCode(address, DefaultBlockParameterName.LATEST).send();
            if (response.hasError()) {
                throw new RuntimeException("eth_getCode RPC error: " + response.getError().getMessage());
            }
            return response.getCode();
        } catch (IOException e) {
            throw new RuntimeException("eth_getCode transport error for " + address, e);
        }
    }

    @Override
    public boolean isValidErc1271Signature(String contractAddress, byte[] hash, byte[] signature) {
        String data = buildCallData(hash, signature);
        try {
            var tx = Transaction.createEthCallTransaction(null, contractAddress, data);
            var response = web3j.ethCall(tx, DefaultBlockParameterName.LATEST).send();
            if (response.hasError()) {
                // Unexpected RPC-level error (not a contract revert — reverts surface as
                // a successful response with "0x" or revert data in getValue()).
                throw new RuntimeException("eth_call RPC error: " + response.getError().getMessage());
            }
            String result = response.getValue();
            // A revert or empty result returns null/"0x"; startsWith check safely handles both.
            return result != null && result.toLowerCase().startsWith("0x1626ba7e");
        } catch (IOException e) {
            throw new RuntimeException("eth_call transport error for " + contractAddress, e);
        }
    }

    /**
     * M3b stub — replace this method with the deployless eth_call adapter next commit.
     * The bytecode artifact required to make the eth_call is supplied in the next step.
     */
    @Override
    public boolean isValidSignatureDeployless(String signer, byte[] hash, byte[] signature) {
        throw new UnsupportedOperationException(
                "EIP-6492 deployless validation: M3b adapter, next commit");
    }

    // ABI encoding of isValidSignature(bytes32 hash, bytes memory signature):
    //   selector (4 bytes)  : 1626ba7e
    //   arg1 (bytes32)      : hash, 32 bytes (static)
    //   arg2 offset (uint256): 64 = 0x40, 32 bytes (points past the two static slots)
    //   arg2 length (uint256): signature.length, 32 bytes
    //   arg2 data            : signature bytes, zero-padded to next 32-byte boundary
    private static String buildCallData(byte[] hash, byte[] signature) {
        HexFormat hex = HexFormat.of();

        byte[] hashPadded = new byte[32];
        System.arraycopy(hash, 0, hashPadded, 0, Math.min(hash.length, 32));

        int sigPaddedLen = ((signature.length + 31) / 32) * 32;
        byte[] sigPadded = new byte[sigPaddedLen];
        System.arraycopy(signature, 0, sigPadded, 0, signature.length);

        return "0x1626ba7e"
                + hex.formatHex(hashPadded)
                + String.format("%064x", 64L)
                + String.format("%064x", (long) signature.length)
                + hex.formatHex(sigPadded);
    }
}
