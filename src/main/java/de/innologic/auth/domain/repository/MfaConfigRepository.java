package de.innologic.auth.domain.repository;

import de.innologic.auth.domain.entity.MfaConfig;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MfaConfigRepository extends JpaRepository<MfaConfig, Long> {
    Optional<MfaConfig> findByCredentialId(Long credentialId);
}
