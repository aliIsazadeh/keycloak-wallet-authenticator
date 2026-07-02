package com.w3auth.backend.identity;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SolanaClusterTest {

    @Test
    void fromClusterName_resolvesKnownClusters() {
        assertThat(SolanaCluster.fromClusterName("mainnet")).isEqualTo(SolanaCluster.MAINNET);
        assertThat(SolanaCluster.fromClusterName("devnet")).isEqualTo(SolanaCluster.DEVNET);
        assertThat(SolanaCluster.fromClusterName("testnet")).isEqualTo(SolanaCluster.TESTNET);
    }

    @Test
    void fromGenesisHash_resolvesKnownHashes() {
        assertThat(SolanaCluster.fromGenesisHash("5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")).isEqualTo(SolanaCluster.MAINNET);
        assertThat(SolanaCluster.fromGenesisHash("EtWTRABZaYq6iMfeYKouRu166VU2xqa1")).isEqualTo(SolanaCluster.DEVNET);
        assertThat(SolanaCluster.fromGenesisHash("4uhcVJyU9pJsqcGL4Cbdhx6dpT2qAM1Z")).isEqualTo(SolanaCluster.TESTNET);
    }

    @Test
    void fromClusterName_rejectsUnknown() {
        assertThatThrownBy(() -> SolanaCluster.fromClusterName("localnet"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported Solana cluster name");
    }

    @Test
    void fromGenesisHash_rejectsUnknown() {
        assertThatThrownBy(() -> SolanaCluster.fromGenesisHash("11111111111111111111111111111111"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported Solana genesis hash");
    }
}
