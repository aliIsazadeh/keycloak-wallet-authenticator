package com.w3auth.backend.infrastructure;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

interface AuthEventJpaRepository extends JpaRepository<AuthEventEntity, UUID> {
}
