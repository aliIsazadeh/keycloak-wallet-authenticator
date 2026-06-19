package com.w3auth.backend.infrastructure;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

interface WalletIdentityRepository extends JpaRepository<WalletIdentityEntity, UUID> {
    Optional<WalletIdentityEntity> findByNamespaceAndAddress(String namespace, String address);
}
