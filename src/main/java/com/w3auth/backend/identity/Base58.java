package com.w3auth.backend.identity;

import java.util.Arrays;

/**
 * Minimal Base58 decoder used to validate Solana Ed25519 public keys.
 *
 * <p>Ported verbatim (decode path only; encode path omitted as unused) from
 * web3j — Apache License 2.0:
 * https://github.com/web3j/web3j/blob/master/crypto/src/main/java/org/web3j/crypto/Base58.java
 * Decode semantics are byte-for-byte identical to the web3j original.
 */
final class Base58 {

    static final char[] ALPHABET =
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();

    private static final int[] INDEXES = new int[128];

    static {
        Arrays.fill(INDEXES, -1);
        for (int i = 0; i < ALPHABET.length; i++) {
            INDEXES[ALPHABET[i]] = i;
        }
    }

    private Base58() {}

    /**
     * Decodes a Base58-encoded string to its raw bytes.
     *
     * @throws IllegalArgumentException if {@code input} contains a character outside
     *         the Base58 alphabet ({@code 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz})
     */
    static byte[] decode(String input) {
        if (input.isEmpty()) {
            return new byte[0];
        }

        // Each leading '1' maps to one leading zero byte in the output.
        int zeros = 0;
        while (zeros < input.length() && input.charAt(zeros) == '1') {
            ++zeros;
        }

        // Map each character to its base-58 digit; reject unknown characters.
        byte[] input58 = new byte[input.length()];
        for (int i = 0; i < input.length(); ++i) {
            char c = input.charAt(i);
            int digit = c < 128 ? INDEXES[c] : -1;
            if (digit < 0) {
                throw new IllegalArgumentException(
                        "Invalid base58 character '" + c + "' at position " + i);
            }
            input58[i] = (byte) digit;
        }

        // Convert base-58 digits to base-256, filling the output buffer from the right.
        byte[] output = new byte[input.length()];
        int outputStart = output.length;
        for (int inputStart = zeros; inputStart < input58.length; ) {
            output[--outputStart] = divmod(input58, inputStart, 58, 256);
            if (input58[inputStart] == 0) {
                ++inputStart;
            }
        }

        // Skip any extra leading zero bytes produced by the base conversion.
        while (outputStart < output.length && output[outputStart] == 0) {
            ++outputStart;
        }

        // Prepend the leading zero bytes (one per leading '1' character).
        return Arrays.copyOfRange(output, outputStart - zeros, output.length);
    }

    private static byte divmod(byte[] number, int firstDigit, int base, int divisor) {
        int remainder = 0;
        for (int i = firstDigit; i < number.length; i++) {
            int digit = number[i] & 0xFF;
            int temp = remainder * base + digit;
            number[i] = (byte) (temp / divisor);
            remainder = temp % divisor;
        }
        return (byte) remainder;
    }
}
