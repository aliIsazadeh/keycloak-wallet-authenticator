package com.w3auth.backend.identity;

/**
 * Maps Solana cluster names to their CAIP-2 genesis block hash prefixes.
 *
 * <p>The CAIP-2 profile for Solana requires the chain reference to be the
 * first 32 characters of the genesis block hash encoded in base58.
 * SIWS (Sign-In With Solana) however requires a cluster string like "mainnet".
 * This enum provides the bidirectional mapping between the two.
 */
public enum SolanaCluster {

    MAINNET("mainnet", "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"),
    DEVNET("devnet", "EtWTRABZaYq6iMfeYKouRu166VU2xqa1"),
    TESTNET("testnet", "4uhcVJyU9pJsqcGL4Cbdhx6dpT2qAM1Z");

    private final String clusterName;
    private final String genesisHash;

    SolanaCluster(String clusterName, String genesisHash) {
        this.clusterName = clusterName;
        this.genesisHash = genesisHash;
    }

    public String clusterName() {
        return clusterName;
    }

    /**
     * The first 32 characters of the genesis block hash in base58.
     */
    public String genesisHash() {
        return genesisHash;
    }

    /**
     * Resolves a cluster name (e.g. "mainnet") to its enum constant.
     *
     * @throws IllegalArgumentException if the cluster name is unsupported
     */
    public static SolanaCluster fromClusterName(String clusterName) {
        for (SolanaCluster cluster : values()) {
            if (cluster.clusterName.equals(clusterName)) {
                return cluster;
            }
        }
        throw new IllegalArgumentException("Unsupported Solana cluster name: " + clusterName);
    }

    /**
     * Resolves a CAIP-2 genesis hash prefix to its enum constant.
     *
     * @throws IllegalArgumentException if the genesis hash is unsupported
     */
    public static SolanaCluster fromGenesisHash(String genesisHash) {
        for (SolanaCluster cluster : values()) {
            if (cluster.genesisHash.equals(genesisHash)) {
                return cluster;
            }
        }
        throw new IllegalArgumentException("Unsupported Solana genesis hash: " + genesisHash);
    }
}
